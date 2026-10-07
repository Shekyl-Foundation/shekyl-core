// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two HTTP stacks speaking to each other.
//!
//! `shekyl-p-fetch` cannot depend on `shekyl-p-serve` on the shipped graph
//! (`SF-D4`). This is a *dev* edge: a SOCKS5h shim in front of a real
//! `PServeEndpoint`, so a mismatch in envelope layout, header set, or
//! request grammar fails here instead of in the field.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_curve_tree::{ServedFrameHeader, LEAF_BYTES};
use shekyl_p_fetch::{
    ContentRefused, ContentVerify, FetchError, FetchTarget, NextMove, PFetchClient, RequestHeader,
    ServingEndpoint, Timeouts,
};
use shekyl_p_serve::{
    PServeEndpoint, PassKey, PassSigner, ProviderError, ShardBody, ShardProvider, SignRefused,
    TestKeySigner, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SHARD: u64 = 3;
const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

struct Fixture {
    shards: HashMap<u64, Arc<[u8]>>,
}

impl ShardProvider for Fixture {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        Ok(self
            .shards
            .get(&shard_id)
            .cloned()
            .and_then(ShardBody::flat))
    }
}

struct Accepting;

impl ContentVerify for Accepting {
    fn verify(&self, _shard_id: u64, _body: &[u8]) -> Result<(), ContentRefused> {
        Ok(())
    }
}

/// SOCKS5 no-auth proxy that CONNECTs by forwarding to `target` regardless
/// of the named destination — the client still has to send ATYP=DOMAIN and
/// the onion name; this shim is the loopback stand-in for the daemon's
/// tor-zone SOCKS, not a second resolver.
async fn socks_forward(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let mut req = [0u8; 4];
                client.read_exact(&mut req).await.ok()?;
                match req[3] {
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await.ok()?;
                        let mut name = vec![0u8; usize::from(len[0])];
                        client.read_exact(&mut name).await.ok()?;
                    }
                    1 => {
                        let mut addr = [0u8; 4];
                        client.read_exact(&mut addr).await.ok()?;
                    }
                    4 => {
                        let mut addr = [0u8; 16];
                        client.read_exact(&mut addr).await.ok()?;
                    }
                    _ => return None,
                }
                let mut port = [0u8; 2];
                client.read_exact(&mut port).await.ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                let mut upstream = TcpStream::connect(target).await.ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .ok()?;
                Some(())
            });
        }
    });
    proxy
}

fn payload() -> Vec<u8> {
    (0..LEAF_BYTES)
        .map(|i| u8::try_from(i % 251).expect("modulus"))
        .collect()
}

/// A real endpoint holding [`SHARD`] behind `signer`, and a client aimed at
/// it through the shim.
async fn stacks(signer: Arc<dyn PassSigner>) -> (PServeEndpoint, PFetchClient) {
    let provider = Arc::new(Fixture {
        shards: HashMap::from([(SHARD, Arc::from(payload().into_boxed_slice()))]),
    });
    let ep = PServeEndpoint::bind(provider, signer).await.expect("bind");
    let proxy = socks_forward(ep.addr()).await;
    let client = PFetchClient::with_timeouts(
        proxy,
        Timeouts {
            dial: Duration::from_millis(500),
            head: Duration::from_millis(1_000),
            body_stall: Duration::from_millis(1_000),
            body_total: Duration::from_millis(2_000),
        },
    );
    (ep, client)
}

fn target(verifying_key: HybridPublicKey, shard_id: u64) -> FetchTarget {
    FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes([0x42; 32]),
        verifying_key,
        shard_id,
    }
}

fn header_at(anchor: u64) -> RequestHeader {
    RequestHeader::with_nonce([0xa5; 32], BlockHeight::from_raw(anchor), [0x5a; 32])
}

#[tokio::test]
async fn fetch_client_accepts_a_real_served_body() {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let public: HybridPublicKey = signer.public_key().clone();
    let (_ep, client) = stacks(Arc::clone(&signer) as Arc<dyn PassSigner>).await;
    let shard = client
        .fetch(
            &target(public, SHARD),
            &header_at(ANCHOR),
            Arc::new(Accepting),
        )
        .await
        .expect("the two stacks speak the same contract");
    assert_eq!(shard.shard_id(), SHARD);
    // Envelope already stripped; remaining bytes are RF-D4 then the
    // segment. The transport crate does not parse the frame — this test
    // does, so a swapped envelope/frame order fails here.
    let mut rest = shard.body();
    let frame = ServedFrameHeader::read(&mut rest).expect("RF-D4 frame ahead of the envelope");
    assert_eq!(frame.leaf_count(), 1);
    assert_eq!(rest, payload().as_slice());
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

    for shard in [SHARD, SHARD + 1] {
        let err = client
            .fetch(
                &target(public.clone(), shard),
                &header_at(OWN_HEIGHT),
                Arc::new(Accepting),
            )
            .await
            .expect_err("an anchor at the tip is outside the gate");
        assert!(matches!(err, FetchError::Rejected), "shard {shard}: {err}");
        assert_eq!(err.next_move(false), NextMove::RetryFreshAnchor);
        assert_eq!(err.next_move(true), NextMove::FailedRead);
    }

    let err = client
        .fetch(
            &target(public.clone(), SHARD + 1),
            &header_at(ANCHOR),
            Arc::new(Accepting),
        )
        .await
        .expect_err("not held");
    assert!(matches!(err, FetchError::Miss), "{err}");
    assert_eq!(err.next_move(false), NextMove::NotHeld);

    // The retry the 400 earns: same `P`, a fresh in-gate anchor.
    client
        .fetch(
            &target(public, SHARD),
            &header_at(ANCHOR),
            Arc::new(Accepting),
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
            &target(any_key(), SHARD),
            &header_at(ANCHOR),
            Arc::new(Accepting),
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
            &target(any_key(), SHARD),
            &header_at(ANCHOR),
            Arc::new(Accepting),
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
