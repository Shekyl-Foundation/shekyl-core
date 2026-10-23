// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The router's splitting and forwarding (CS-3 §4.2).

use std::sync::{Arc, Mutex};

use shekyl_levin::{notify, BucketHead, Flags, SyncCommand, HEADER_SIZE};
use shekyl_seam::{Endpoint, Post, SocketId, SyncPayload};
use tokio::sync::mpsc;

use super::{Fed, Forward, Routed, Router, Split};

fn recorder() -> (Forward, Arc<Mutex<Vec<Post>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    (
        Arc::new(move |post| sink.lock().expect("unpoisoned").push(post)),
        seen,
    )
}

fn sync_bucket(command: SyncCommand, payload: &[u8]) -> Vec<u8> {
    notify(command.wire_id(), payload)
}

fn other_bucket(payload: &[u8]) -> Vec<u8> {
    // 2002, new transactions: a C++ command.
    notify(2002, payload)
}

#[test]
fn a_split_routes_sync_whole_and_streams_the_rest() {
    let mut split = Split::default();
    let a = other_bucket(b"cpp-one");
    let s = sync_bucket(SyncCommand::RequestHeaders, b"sync-payload");
    let b = other_bucket(b"cpp-two");
    let mut stream = Vec::new();
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&s);
    stream.extend_from_slice(&b);
    // Every chunking gives the same split.
    for cut in 1..stream.len() {
        let mut split = Split::default();
        let first = split.feed(&stream[..cut]);
        let second = split.feed(&stream[cut..]);
        let mut forward = first.forward.clone();
        forward.extend_from_slice(&second.forward);
        let mut messages = first.messages.clone();
        messages.extend(second.messages.clone());
        let mut expected = a.clone();
        expected.extend_from_slice(&b);
        assert_eq!(forward, expected, "cut at {cut}");
        assert_eq!(
            messages,
            vec![(SyncCommand::RequestHeaders, b"sync-payload".to_vec())],
            "cut at {cut}"
        );
    }
    let whole = split.feed(&stream);
    assert_eq!(whole.messages.len(), 1);
}

#[test]
fn a_bad_signature_sends_the_rest_raw() {
    let mut split = Split::default();
    let mut bad = sync_bucket(SyncCommand::RequestHeaders, b"x");
    bad[0] ^= 0xff;
    let fed = split.feed(&bad);
    assert_eq!(fed.forward, bad);
    assert!(fed.messages.is_empty());
    // And everything after it, even a well-formed sync bucket.
    let good = sync_bucket(SyncCommand::RequestHeaders, b"y");
    assert_eq!(
        split.feed(&good),
        Fed {
            forward: good,
            messages: Vec::new()
        }
    );
}

#[test]
fn a_sync_bucket_the_router_does_not_admit_goes_to_cpp() {
    let over = SyncCommand::RequestHeaders.payload_cap() + 1;
    let head = |flags: Flags, len: u64, expect: bool| {
        BucketHead::make(SyncCommand::RequestHeaders.wire_id(), len, flags, expect).write()
    };
    for (name, raw) in [
        ("over its cap", head(Flags::REQUEST, over, false)),
        ("a response", head(Flags::RESPONSE, 0, false)),
        ("an invoke", head(Flags::REQUEST, 0, true)),
        (
            "a fragment",
            head(Flags::REQUEST.union(Flags::BEGIN), 0, false),
        ),
        ("an undefined flag", head(Flags::from_bits(0x11), 0, false)),
    ] {
        let mut split = Split::default();
        let fed = split.feed(&raw);
        assert_eq!(fed.forward, raw.to_vec(), "{name}");
        assert!(fed.messages.is_empty(), "{name}");
    }
    assert_eq!(HEADER_SIZE, 29);
}

#[test]
fn a_claimed_length_is_not_an_allocation() {
    let mut split = Split::default();
    let len = SyncCommand::ResponseBodies.payload_cap();
    let raw = BucketHead::make(
        SyncCommand::ResponseBodies.wire_id(),
        len,
        Flags::REQUEST,
        false,
    )
    .write();
    let fed = split.feed(&raw);
    assert!(fed.forward.is_empty() && fed.messages.is_empty());
    match &split.state {
        super::State::Sync { payload, .. } => assert!(payload.capacity() <= super::RESERVE),
        other => panic!("{other:?}"),
    }
}

fn endpoint() -> Endpoint {
    Endpoint::TorInbound
}

fn socket(raw: u64) -> SocketId {
    SocketId::from_ffi(raw).expect("not zero")
}

#[test]
fn pass_through_forwards_every_post_unchanged() {
    let (forward, seen) = recorder();
    let router = Router::pass_through(forward);
    let id = socket(7);
    let bytes = sync_bucket(SyncCommand::RequestHeaders, b"p");
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    router.post(Post::Deliver {
        id,
        connector: endpoint().connector(),
        bytes: bytes.clone(),
    });
    let seen = seen.lock().expect("unpoisoned");
    assert_eq!(seen.len(), 2);
    assert!(matches!(&seen[1], Post::Deliver { bytes: b, .. } if *b == bytes));
}

#[test]
fn attached_routes_sync_and_forwards_one_post_per_chunk() {
    let (forward, seen) = recorder();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(9);
    let connector = endpoint().connector();
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    assert_eq!(
        rx.try_recv().expect("established"),
        Routed::Established { id, connector }
    );
    let sync = SyncPayload {
        current_height: 5,
        cumulative_difficulty: 9,
        cumulative_difficulty_top64: 0,
        top_id: [4; 32],
    };
    router.post(Post::HandshakeResult {
        id,
        connector,
        sync,
    });
    assert_eq!(rx.try_recv().expect("claim"), Routed::Claim { id, sync });

    // A chunk with a C++ bucket and a sync bucket: one forward, one message.
    let mut chunk = other_bucket(b"tx");
    chunk.extend_from_slice(&sync_bucket(SyncCommand::RequestBodies, b"rb"));
    router.post(Post::Deliver {
        id,
        connector,
        bytes: chunk,
    });
    assert_eq!(
        rx.try_recv().expect("message"),
        Routed::Message {
            id,
            command: SyncCommand::RequestBodies,
            payload: b"rb".to_vec()
        }
    );
    assert!(
        rx.try_recv().is_err(),
        "no Finished: the handler finishes it"
    );

    // A chunk that is all sync: the owner finishes it.
    router.post(Post::Deliver {
        id,
        connector,
        bytes: sync_bucket(SyncCommand::RequestHeaders, b""),
    });
    assert!(matches!(rx.try_recv(), Ok(Routed::Message { .. })));
    assert_eq!(rx.try_recv().expect("finished"), Routed::Finished { id });

    let forwarded = seen.lock().expect("unpoisoned");
    let delivers: Vec<_> = forwarded
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(delivers, vec![other_bucket(b"tx")]);
    assert!(matches!(forwarded[1], Post::HandshakeResult { .. }));
}

#[test]
fn a_gone_owner_turns_the_router_back_to_pass_through() {
    let (forward, seen) = recorder();
    let (tx, rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(3);
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    drop(rx);
    let bytes = sync_bucket(SyncCommand::RequestHeaders, b"q");
    router.post(Post::Deliver {
        id,
        connector: endpoint().connector(),
        bytes: bytes.clone(),
    });
    let seen = seen.lock().expect("unpoisoned");
    assert!(matches!(&seen[1], Post::Deliver { bytes: b, .. } if *b == bytes));
}
