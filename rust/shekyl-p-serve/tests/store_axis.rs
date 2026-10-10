// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end on the axis the production provider lives on: body store →
//! endpoint → loopback fetch → the streamed bytes are the frame that was
//! put, and the countersignature binds them.
//!
//! A missing shard is an ordinary 404. Erase is how a released pin
//! becomes a miss — not a 503.

use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_archival_retention::pass_anchor::{pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::BlockHeight;
use shekyl_p_serve::{
    PServeEndpoint, PassSigner, ShardProvider, StoreShardProvider, TestKeySigner,
    REQUEST_HEADER_NAME, SIGNATURE_ENVELOPE_LEN,
};
use shekyl_p_store::{BodyStore, StoreKey};
use shekyl_types::ShardId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The test persona's height and the in-gate anchor a requester at the
/// same tip attaches (`tip − 720`).
const OWN_HEIGHT: u64 = 20_000;
const ANCHOR_HEIGHT: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const NONCE: [u8; 32] = [0x3c; 32];
const ANCHOR_HASH: [u8; 32] = [0xc3; 32];

/// Opaque `shard_frame` stand-in: the loop must stream it exactly.
const FRAME: &[u8] = b"\x01\x01not-a-real-frame-but-the-bytes-the-loop-must-reproduce";

fn key() -> StoreKey {
    StoreKey::from_bytes([0x5a; 32])
}

fn shard(n: u64) -> ShardId {
    ShardId::from_raw(n)
}

async fn bind(provider: Arc<dyn ShardProvider>) -> (PServeEndpoint, Arc<TestKeySigner>) {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let ep = PServeEndpoint::bind(provider, Arc::clone(&signer) as Arc<dyn PassSigner>)
        .await
        .expect("bind endpoint");
    (ep, signer)
}

async fn fetch(addr: SocketAddr, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let header = encode_request_header(&pass_request_header_bytes(
        &NONCE,
        BlockHeight::from_raw(ANCHOR_HEIGHT),
        &ANCHOR_HASH,
    ));
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nhost: x\r\n{REQUEST_HEADER_NAME}: {header}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    out
}

/// Split a 200 response after its head into (countersignature, body).
fn envelope_of(response: &[u8]) -> (HybridSignature, &[u8]) {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    let after_head = &response[end + 4..];
    let (body, sig) = after_head.split_at(after_head.len() - SIGNATURE_ENVELOPE_LEN);
    (
        HybridSignature::from_canonical_bytes(sig).expect("served body ends with a signature"),
        body,
    )
}

#[tokio::test]
async fn served_shard_is_the_put_frame() {
    let store = BodyStore::open_ephemeral(key()).expect("open");
    store.put_shard(shard(0), FRAME).expect("put");
    let provider = StoreShardProvider::new(store.reader());
    let (ep, signer) = bind(Arc::new(provider)).await;

    let response = fetch(ep.addr(), "/shard/0").await;
    let (signature, body) = envelope_of(&response);

    verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(ANCHOR_HEIGHT),
        &ANCHOR_HASH,
        0,
        &pass_delivery_digest(&NONCE, body),
        &signature,
    )
    .expect("the countersignature covers this request's header, shard id and delivered bytes");

    assert_eq!(body, FRAME, "the loop streams the opened body exactly");
    assert_eq!(ep.served_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn missing_shards_are_indistinguishable_404s() {
    let store = BodyStore::open_ephemeral(key()).expect("open");
    store.put_shard(shard(0), FRAME).expect("put");
    let (ep, _) = bind(Arc::new(StoreShardProvider::new(store.reader()))).await;

    let never_held = fetch(ep.addr(), "/shard/1").await;
    let unknown = fetch(ep.addr(), "/shard/77").await;
    assert_eq!(never_held, unknown);
    assert!(unknown.starts_with(b"HTTP/1.1 404 "), "not held is the 404");
    let bad_route = fetch(ep.addr(), "/nope").await;
    assert!(bad_route.starts_with(b"HTTP/1.1 400 "));
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.lookup_failure_count(), 0, "a refusal is not a failure");
}

#[tokio::test]
async fn erase_makes_a_held_shard_an_ordinary_404() {
    let store = BodyStore::open_ephemeral(key()).expect("open");
    store.put_shard(shard(0), FRAME).expect("put");
    store.erase_shard(shard(0)).expect("erase");

    let (ep, _) = bind(Arc::new(StoreShardProvider::new(store.reader()))).await;
    let gone = fetch(ep.addr(), "/shard/0").await;
    assert!(
        gone.starts_with(b"HTTP/1.1 404 "),
        "erase is a miss, not a store fault"
    );
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
}

#[test]
fn provider_body_is_exactly_the_put_bytes() {
    let store = BodyStore::open_ephemeral(key()).expect("open");
    store.put_shard(shard(0), FRAME).expect("put");
    let provider = StoreShardProvider::new(store.reader());
    let mut body = provider
        .shard_bytes(0)
        .expect("lookup")
        .expect("held shard");
    let declared = body.remaining_bytes();
    assert_eq!(declared, FRAME.len());

    let mut bytes = Vec::new();
    while let Some(chunk) = body.next_chunk(7).expect("chunk") {
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(bytes, FRAME, "the body matches its content-length");
}
