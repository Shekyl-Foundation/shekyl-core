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

use shekyl_curve_tree::{
    leaves_per_segment, recompute_segment_r_k, BlockHeight, Gindex, LeafEntry, LeafStore,
    OutputIdentity, SegmentId, TargetKind,
};
use shekyl_p_serve::{PServeEndpoint, ServeSetPin, ShardProvider, StoreShardProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A full segment of distinct canonical leaves — distinct so a
/// stride/offset bug in the read cannot still hash to the right `R_k`.
fn segment_entries() -> Vec<LeafEntry> {
    (0..leaves_per_segment())
        .map(|i| {
            let gindex = u64::try_from(i).expect("index fits u64");
            let mut leaf = [1u8; 128];
            leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
            LeafEntry {
                gindex: Gindex(gindex),
                maturity: BlockHeight(0),
                creation_height: BlockHeight(0),
                leaf,
                identity: OutputIdentity {
                    output_key: [1u8; 32],
                    commitment: Some([2u8; 32]),
                    h_pqc: [3u8; 32],
                    target: TargetKind::TaggedKey,
                },
            }
        })
        .collect()
}

async fn fetch(addr: SocketAddr, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    out
}

fn body_of(response: &[u8]) -> &[u8] {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    &response[end + 4..]
}

#[tokio::test]
async fn served_shard_recomputes_to_the_committed_r_k() {
    // Freeze segment 0 (append a full segment past the eligibility
    // height), pin the serve-set, prune — the serving-daemon startup
    // sequence — then serve and run the witness's own verification.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");

    let provider = StoreShardProvider::new(Arc::clone(&store));
    let pins = provider.pin_serve_set(&[0, 1]).expect("pin serve set");
    assert_eq!(
        pins,
        vec![
            ServeSetPin::Pinned { shard_id: 0 },
            // Bonded-before-freeze is legal; nothing to pin yet.
            ServeSetPin::NotYetFrozen { shard_id: 1 },
        ]
    );
    // The prune a wallet lifecycle would run: the pin keeps shard 0
    // servable through it.
    store.prune_frozen(&[]).expect("prune");

    let ep = PServeEndpoint::bind(Arc::new(provider))
        .await
        .expect("bind endpoint");

    let response = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
    let body = body_of(&response);
    assert_eq!(body.len(), leaves_per_segment() * 128, "whole-shard read");

    // The witness check: chunk the fetched bytes back into leaves,
    // recompute the sub-root, compare against the chain-committed record.
    let leaves: Vec<[u8; 128]> = body
        .chunks_exact(128)
        .map(|c| c.try_into().expect("128-byte leaf"))
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
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");
    let ep = PServeEndpoint::bind(Arc::new(StoreShardProvider::new(Arc::clone(&store))))
        .await
        .expect("bind");

    let unfrozen = fetch(ep.addr(), "/x-provisional/v0/shard/1").await;
    let unknown = fetch(ep.addr(), "/x-provisional/v0/shard/77").await;
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
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");
    store.prune_frozen(&[]).expect("prune without pinning");

    let ep = PServeEndpoint::bind(Arc::new(StoreShardProvider::new(Arc::clone(&store))))
        .await
        .expect("bind");
    let pruned = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
    let bad_route = fetch(ep.addr(), "/nope").await;
    assert_eq!(pruned, bad_route, "store failure renders the shared 404");
    assert_eq!(ep.lookup_failure_count(), 1, "but the counter names it");
    assert_eq!(ep.served_count(), 0);
}

#[test]
fn provider_flattens_exactly_the_store_chunks() {
    // Storeless sanity on the flattening: the provider's bytes are the
    // store's leaves in order, no padding, no reordering.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let entries = segment_entries();
    store
        .append_block_deltas(&entries, &[], &[], BlockHeight(10_000))
        .expect("append and freeze");
    let provider = StoreShardProvider::new(store);
    let bytes = provider
        .shard_bytes(0)
        .expect("lookup")
        .expect("frozen shard");
    assert_eq!(bytes.len(), entries.len() * 128);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(&bytes[i * 128..(i + 1) * 128], &entry.leaf[..]);
    }
}
