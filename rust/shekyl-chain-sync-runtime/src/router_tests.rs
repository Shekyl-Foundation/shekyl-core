// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The router's splitting and forwarding (CS-3 §4.2).

use std::sync::{Arc, Mutex};

use shekyl_levin::{
    invoke, notify, response, BucketHead, DefinedCommand, Flags, SyncCommand, COMMAND_HANDSHAKE,
    COMMAND_TIMED_SYNC, HEADER_SIZE, NOTIFY_NEW_COMPACT_BLOCK,
};
use shekyl_seam::{Endpoint, Post, SocketId, SyncPayload};
use tokio::sync::mpsc;

use super::{Admitted, Fed, Forward, Routed, Router, Split, Tapped};

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
            vec![(
                Admitted::Sync(SyncCommand::RequestHeaders),
                b"sync-payload".to_vec()
            )],
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
            ..Fed::default()
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
    // The header names a 100_000_000-byte payload. Nothing of it has
    // arrived, so the split holds the header and does not allocate it.
    assert!(
        split.raw.capacity() < 64 * 1024,
        "capacity {}",
        split.raw.capacity()
    );
    assert!(matches!(split.state, super::State::Sync { .. }));
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

#[test]
fn a_partial_header_reaches_cpp_when_the_owner_leaves() {
    let (forward, seen) = recorder();
    let (tx, rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(4);
    let connector = endpoint().connector();
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    let bucket = other_bucket(b"cpp-bytes");
    let cut = 10;
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[..cut].to_vec(),
    });
    drop(rx);
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[cut..].to_vec(),
    });
    let seen = seen.lock().expect("unpoisoned");
    let delivers: Vec<_> = seen
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(delivers, vec![bucket]);
}

#[test]
fn a_cpp_payload_already_handed_on_is_not_sent_twice() {
    let (forward, seen) = recorder();
    let (tx, rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(5);
    let connector = endpoint().connector();
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    let bucket = other_bucket(b"cpp-bytes");
    let cut = HEADER_SIZE + 2;
    assert!(cut < bucket.len());
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[..cut].to_vec(),
    });
    drop(rx);
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[cut..].to_vec(),
    });
    let seen = seen.lock().expect("unpoisoned");
    let delivers: Vec<_> = seen
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(delivers, vec![&bucket[..cut], &bucket[cut..]]);
}

#[test]
fn a_partial_sync_bucket_is_handed_to_cpp_whole_when_the_owner_leaves() {
    let (forward, seen) = recorder();
    let (tx, rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(6);
    let connector = endpoint().connector();
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    let bucket = sync_bucket(SyncCommand::RequestHeaders, b"sync-payload");
    let cut = HEADER_SIZE + 3;
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[..cut].to_vec(),
    });
    drop(rx);
    router.post(Post::Deliver {
        id,
        connector,
        bytes: bucket[cut..].to_vec(),
    });
    let seen = seen.lock().expect("unpoisoned");
    let delivers: Vec<_> = seen
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(delivers, vec![bucket]);
}

/// The daemon's router before the cutover is pass-through: every post
/// reaches the C++ handler unchanged, including chain sync's own commands
/// and the messages the claim tap copies, and nothing reaches an owner.
#[test]
fn the_daemons_pass_through_router_changes_nothing_live() {
    let (forward, seen) = recorder();
    let sink = Router::pass_through(forward).into_sink();
    let id = socket(11);
    let connector = endpoint().connector();
    let sync = SyncPayload {
        current_height: 3,
        cumulative_difficulty: 3,
        cumulative_difficulty_top64: 0,
        top_id: [1; 32],
    };
    let mut posts = vec![
        Post::Established {
            id,
            endpoint: endpoint(),
        },
        Post::HandshakeResult {
            id,
            connector,
            sync,
        },
    ];
    for command in SyncCommand::ALL {
        posts.push(Post::Deliver {
            id,
            connector,
            bytes: sync_bucket(command, b"payload"),
        });
    }
    posts.push(Post::Deliver {
        id,
        connector,
        bytes: invoke(COMMAND_HANDSHAKE, b"a handshake"),
    });
    posts.push(Post::Deliver {
        id,
        connector,
        bytes: other_bucket(b"relay"),
    });
    for post in posts.clone() {
        sink(post);
    }
    assert_eq!(*seen.lock().expect("unpoisoned"), posts);
}

/// An attached router's claim tap (CS-Q10): a handshake request and both
/// timed-sync directions reach the C++ handler unchanged, and the owner
/// gets a copy of each payload. A payload split across chunks is one
/// copy. A fragment and an over-cap payload are not copied. Red edit: tap
/// nothing.
#[test]
fn an_attached_router_taps_the_messages_that_carry_a_claim() {
    let (forward, seen) = recorder();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(12);
    let connector = endpoint().connector();
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    let _established = rx.try_recv().expect("established");
    let handshake = invoke(COMMAND_HANDSHAKE, b"handshake-payload");
    let request = invoke(COMMAND_TIMED_SYNC, b"request-payload");
    let reply = response(COMMAND_TIMED_SYNC, b"response-payload");
    let mut stream = handshake.clone();
    stream.extend_from_slice(&request);
    stream.extend_from_slice(&reply);
    // Split mid-payload, so a copy spans two chunks.
    let cut = handshake.len() - 4;
    for chunk in [&stream[..cut], &stream[cut..]] {
        router.post(Post::Deliver {
            id,
            connector,
            bytes: chunk.to_vec(),
        });
    }
    let taps: Vec<Routed> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(
        taps,
        vec![
            Routed::Tap {
                id,
                kind: Tapped::HandshakeRequest,
                payload: b"handshake-payload".to_vec()
            },
            Routed::Tap {
                id,
                kind: Tapped::TimedSyncRequest,
                payload: b"request-payload".to_vec()
            },
            Routed::Tap {
                id,
                kind: Tapped::TimedSyncResponse,
                payload: b"response-payload".to_vec()
            },
        ]
    );
    let forwarded: Vec<u8> = seen
        .lock()
        .expect("unpoisoned")
        .iter()
        .filter_map(|post| match post {
            Post::Deliver { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(forwarded, stream, "the C++ handler sees every byte");

    // A fragment, and a handshake past its cap, are not copied.
    let mut fragment = invoke(COMMAND_HANDSHAKE, b"x");
    let mut head =
        BucketHead::read(&fragment[..HEADER_SIZE].try_into().expect("a header")).expect("a header");
    head.flags = head.flags.union(Flags::BEGIN);
    fragment[..HEADER_SIZE].copy_from_slice(&head.write());
    let cap = DefinedCommand::Handshake.payload_cap();
    let oversize = invoke(
        COMMAND_HANDSHAKE,
        &vec![0; usize::try_from(cap + 1).expect("a cap")],
    );
    for bytes in [fragment, oversize] {
        router.post(Post::Deliver {
            id,
            connector,
            bytes,
        });
    }
    assert!(
        std::iter::from_fn(|| rx.try_recv().ok()).all(|item| !matches!(item, Routed::Tap { .. })),
        "a fragment or an over-cap payload was copied"
    );
}

/// An attached router keeps an announced block (2008) for the owner; the
/// transaction relay beside it still reaches the C++ handler.
#[test]
fn an_attached_router_hands_an_announcement_to_the_owner() {
    let (forward, seen) = recorder();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let router = Router::attached(forward, tx);
    let id = socket(21);
    router.post(Post::Established {
        id,
        endpoint: endpoint(),
    });
    let _established = rx.try_recv().expect("established");
    let mut chunk = notify(NOTIFY_NEW_COMPACT_BLOCK, b"a block");
    chunk.extend_from_slice(&other_bucket(b"tx"));
    router.post(Post::Deliver {
        id,
        connector: endpoint().connector(),
        bytes: chunk,
    });
    assert_eq!(
        rx.try_recv().expect("the announcement"),
        Routed::Announce {
            id,
            payload: b"a block".to_vec()
        }
    );
    let forwarded = seen.lock().expect("unpoisoned");
    assert!(
        matches!(forwarded.last(), Some(Post::Deliver { bytes, .. }) if *bytes == other_bucket(b"tx"))
    );
}
