// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end on the axis the serving path lives on: store → pin →
//! endpoint → loopback fetch → **recompute `R_k` from the fetched bytes and
//! match the chain-committed record** — exactly the check a witness runs on
//! the far side of the rendezvous (`ARCHIVAL_CHALLENGE_MECHANISM.md` §2:
//! the response is self-authenticating by content). A corrupted store, a
//! stride bug in the serving read, or a truncated write all fail *this*
//! check, which is the one that decides serve credit.

use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_archival_retention::pass_anchor::{pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_archival_retention::verify_pass_transcript;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::{
    leaves_per_segment, recompute_segment_r_k, BlockHeight, Gindex, LeafEntry, LeafStore,
    OutputIdentity, SegmentId, SegmentPin, ServedFrameHeader, ServingReader, TargetKind,
    LEAF_BYTES,
};
use shekyl_p_serve::{
    PServeEndpoint, PassSigner, ShardProvider, StoreShardProvider, TestKeySigner,
    REQUEST_HEADER_NAME, SIGNATURE_ENVELOPE_LEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The test persona's height and the in-gate anchor a requester at the
/// same tip attaches (`tip − 720`).
const OWN_HEIGHT: u64 = 20_000;
const ANCHOR_HEIGHT: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const NONCE: [u8; 32] = [0x3c; 32];
const ANCHOR_HASH: [u8; 32] = [0xc3; 32];

async fn bind(provider: Arc<dyn ShardProvider>) -> (PServeEndpoint, Arc<TestKeySigner>) {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let ep = PServeEndpoint::bind(provider, Arc::clone(&signer) as Arc<dyn PassSigner>)
        .await
        .expect("bind endpoint");
    (ep, signer)
}

/// A full segment of distinct canonical leaves — distinct so a
/// stride/offset bug in the read cannot still hash to the right `R_k`.
fn segment_entries() -> Vec<LeafEntry> {
    (0..leaves_per_segment())
        .map(|i| {
            let gindex = u64::try_from(i).expect("index fits u64");
            let mut leaf = [1u8; 128];
            leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
            LeafEntry {
                gindex: Gindex::from_raw(gindex),
                maturity: BlockHeight::from_raw(0),
                creation_height: BlockHeight::from_raw(0),
                leaf,
                identity: OutputIdentity {
                    output_key: shekyl_curve_tree::OneTimePubkey::from_bytes([1u8; 32]),
                    commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes([2u8; 32])),
                    cm: [3u8; 32],
                    target: TargetKind::TaggedKey,
                },
            }
        })
        .collect()
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

/// Split a 200 response after its head into (countersignature, framed body).
fn envelope_of(response: &[u8]) -> (HybridSignature, &[u8]) {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    let (sig, body) = response[end + 4..].split_at(SIGNATURE_ENVELOPE_LEN);
    (
        HybridSignature::from_canonical_bytes(sig).expect("served body leads with a signature"),
        body,
    )
}

#[tokio::test]
async fn served_shard_recomputes_to_the_committed_r_k() {
    // Freeze segment 0 (append a full segment past the eligibility
    // height), pin the serve-set, prune — the serving-daemon startup
    // sequence — then serve and run the witness's own verification.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze segment 0");

    let pins = store.pin_serve_set(&[0, 1]).expect("pin serve set");
    assert_eq!(
        pins,
        vec![
            (0, SegmentPin::PinnedServable),
            // Bonded-before-freeze is legal; nothing to pin yet.
            (1, SegmentPin::PinnedNotYetFrozen),
        ]
    );
    let provider = StoreShardProvider::new(ServingReader::new(Arc::clone(&store)));
    // The prune a wallet lifecycle would run: the pin keeps shard 0
    // servable through it.
    store.prune_frozen(&[]).expect("prune");

    let (ep, signer) = bind(Arc::new(provider)).await;

    let response = fetch(ep.addr(), "/shard/0").await;
    let (signature, mut body) = envelope_of(&response);

    // The witness's *first* act (`SF-D8`): the response is bound to the
    // request it made. Verified through the same consensus function the
    // daemon runs at admission, against the P pubkey the bond record holds.
    verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(ANCHOR_HEIGHT),
        &ANCHOR_HASH,
        0,
        &signature,
    )
    .expect("the countersignature covers this request's header and shard id");

    // Then the frame (`RF-D4`): it says how
    // many leaves the response carries and how many bytes follow them that
    // are *not* part of the `R_k` input. This test is the nearest thing to
    // a fetcher that exists, so it reads the format the way one will —
    // through `ServedFrameHeader::read`, not by assuming the body starts at
    // byte zero.
    let frame = ServedFrameHeader::read(&mut body).expect("served body carries a frame header");
    assert_eq!(frame.leaf_count(), leaves_per_segment() as u64);
    assert_eq!(frame.padding_len(), 0, "writers emit zero padding");
    assert_eq!(
        body.len() as u64,
        frame.segment_bytes() + frame.padding_len(),
        "the frame accounts for every byte after the header"
    );

    // The witness check: chunk the *segment* bytes back into leaves,
    // recompute the sub-root, compare against the chain-committed record.
    // Padding, when a scheme exists, is excluded here by construction —
    // the slice is taken at `segment_bytes()`, not at the end of the body.
    let segment = &body[..usize::try_from(frame.segment_bytes()).expect("segment fits usize")];
    let leaves: Vec<[u8; LEAF_BYTES]> = segment
        .chunks_exact(LEAF_BYTES)
        .map(|c| c.try_into().expect("whole leaf"))
        .collect();
    let recomputed = recompute_segment_r_k(&leaves).expect("recompute R_k");
    let record = store
        .frozen_segment(SegmentId(0))
        .expect("read record")
        .expect("segment 0 frozen");
    assert_eq!(
        recomputed, record.r_k,
        "served bytes must verify against the committed R_k"
    );
    assert_eq!(ep.served_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn unfrozen_and_unknown_shards_are_indistinguishable_404s() {
    // Segment 1 exists in the serve-set but has not frozen; segment 77
    // does not exist at all. Both must render the identical 404 —
    // holdings and freeze progress are chain-public, but this endpoint
    // must not become a second, unauthenticated oracle for them.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze segment 0");
    let (ep, _) = bind(Arc::new(StoreShardProvider::new(ServingReader::new(
        Arc::clone(&store),
    ))))
    .await;

    let unfrozen = fetch(ep.addr(), "/shard/1").await;
    let unknown = fetch(ep.addr(), "/shard/77").await;
    let bad_route = fetch(ep.addr(), "/nope").await;
    assert_eq!(unfrozen, unknown);
    assert_eq!(unknown, bad_route);
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.lookup_failure_count(), 0, "a refusal is not a failure");
}

#[tokio::test]
async fn unpinned_prune_surfaces_as_a_counted_failure_not_a_distinct_response() {
    // The silent-slash precursor, end to end: freeze, prune WITHOUT
    // pinning, serve. The wire shows the shared 404 (store health is not
    // probeable); the local counter shows exactly what went wrong.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze segment 0");
    store.prune_frozen(&[]).expect("prune without pinning");

    let (ep, _) = bind(Arc::new(StoreShardProvider::new(ServingReader::new(
        Arc::clone(&store),
    ))))
    .await;
    let pruned = fetch(ep.addr(), "/shard/0").await;
    let bad_route = fetch(ep.addr(), "/nope").await;
    assert_eq!(pruned, bad_route, "store failure renders the shared 404");
    assert_eq!(ep.lookup_failure_count(), 1, "but the counter names it");
    assert_eq!(ep.served_count(), 0);
}

#[test]
fn provider_body_is_exactly_the_store_leaves_in_order() {
    // The production body is the store's leaves in tree order — no
    // padding, no reordering — and it streams: the length is exact before
    // the first chunk is read, which is what lets the response head be
    // committed before the store is touched.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let entries = segment_entries();
    store
        .append_block_deltas(&entries, &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze");
    let provider = StoreShardProvider::new(ServingReader::new(store));
    let mut body = provider
        .shard_bytes(0)
        .expect("lookup")
        .expect("frozen shard");
    let declared = body.remaining_bytes();
    assert_eq!(declared, entries.len() * 128);

    let mut bytes = Vec::new();
    // A chunk size that is not a multiple of the leaf width, so a reader
    // that quietly assumes leaf-aligned chunks fails here.
    while let Some(chunk) = body.next_chunk(3_000).expect("chunk") {
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(bytes.len(), declared, "the body matches its content-length");
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(&bytes[i * 128..(i + 1) * 128], &entry.leaf[..]);
    }
}

#[test]
fn an_unfrozen_serve_set_member_is_pinned_before_it_freezes() {
    // The window this closes: shard bonded, not yet frozen. If the pin
    // waited for the freeze, a prune landing between the freeze and the
    // next re-pin would discard the bytes permanently. Pinning ahead makes
    // the survival of a bonded shard independent of which timer fires
    // first.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let provider = StoreShardProvider::new(ServingReader::new(Arc::clone(&store)));
    assert_eq!(
        store.pin_serve_set(&[0]).expect("pin ahead of freeze"),
        vec![(0, SegmentPin::PinnedNotYetFrozen)]
    );

    // Freeze, then prune with no further pinning call at all.
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight::from_raw(10_000))
        .expect("append and freeze segment 0");
    store.prune_frozen(&[]).expect("prune");

    let body = provider
        .shard_bytes(0)
        .expect("lookup")
        .expect("the advance pin kept the shard servable");
    assert_eq!(body.remaining_bytes(), leaves_per_segment() * 128);
}
