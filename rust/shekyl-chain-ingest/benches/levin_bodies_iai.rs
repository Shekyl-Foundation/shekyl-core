// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One inbound body response, from session bytes to its decoded payload
//! (`BENCHMARK_ALIGNMENT.md` BA-T45). Two calls, each its own row:
//!
//! - **`crypto_bench_levin_frame_read`**: `BucketReader::feed` and
//!   `next_message` over one whole Levin frame, on a reader past the
//!   handshake: the header parsed and checked against the command's cap,
//!   and the payload handed out. What the session layer does with every
//!   record's plaintext (`shekyl-p2p-session`).
//! - **`crypto_bench_levin_bodies_decode`**: `ResponseBodies::decode` and
//!   `check_form` over that payload: the portable-storage parse of the
//!   body list under its caps, and the comparison with the request. The
//!   first thing the sync model does with a body response
//!   (`shekyl-chain-sync` `runs/bodies.rs`).
//!
//! The frame is the notification (command 2014) a serving node sends for a
//! request of the tail of a block-path fixture's chain: the bytes
//! `serve_bodies` and the Levin encoder produce in setup,
//! so the decoder reads what the serving side writes. The subject block
//! lists the unit fixture's spends, each carried whole.
//!
//! The bench is this crate's for the store the response is served from
//! (`bench_support.rs`). The row shares the body exchange's path set
//! with the serve: `shekyl-levin` is a normal dependency of
//! `shekyl-chain-sync-runtime`, so a change to the decoder selects both.
//!
//! An instruction count on the CI runner's x86, never a floor figure
//! (rule 76).

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_sync_runtime::serve::serve_bodies;
use shekyl_levin::{
    notify, BucketReader, PortableMap, Received, RequestBodies, ResponseBodies,
    DEFAULT_MAX_PACKET_SIZE,
};

#[path = "support/tail.rs"]
mod tail;
use tail::{RequestedTail, SUBJECT_SPENDS, TAIL_BLOCKS};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out_unit.corpus");

/// The body response's command (`NOTIFY_RESPONSE_BODIES`).
const RESPONSE_BODIES: u32 = 2014;

/// The request for the fixture chain's tail, and the encoded response a
/// serving node answers it with.
fn served(corpus: &[u8]) -> (Vec<[u8; 32]>, Vec<u8>) {
    let tail = RequestedTail::connected(corpus);
    let response = serve_bodies(
        tail.chain.store(),
        &RequestBodies {
            hashes: tail.hashes.clone(),
        },
    )
    .expect("the serve");
    assert_eq!(response.bodies.len(), TAIL_BLOCKS, "every body is sent");
    assert_eq!(
        response.bodies[TAIL_BLOCKS - 1].txs.len(),
        SUBJECT_SPENDS,
        "the subject carries its spends"
    );
    let payload = response.store().expect("the response encodes");
    (tail.hashes, payload)
}

/// A reader past the handshake, and the response as one frame.
fn framed(corpus: &[u8]) -> (BucketReader, Vec<u8>) {
    let (_, payload) = served(corpus);
    let mut reader = BucketReader::new();
    reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
    (reader, notify(RESPONSE_BODIES, &payload))
}

#[library_benchmark]
#[bench::bodies_response(args = (SPEND_1IN_2OUT), setup = framed)]
fn crypto_bench_levin_frame_read(
    (mut reader, frame): (BucketReader, Vec<u8>),
) -> (BucketReader, Vec<u8>, Vec<u8>) {
    reader.feed(black_box(&frame)).expect("the frame is fed");
    let payload = match black_box(reader.next_message().expect("the frame is whole")) {
        Some(Received::Notification {
            command: RESPONSE_BODIES,
            payload,
        }) => payload,
        other => panic!("one body-response notification: {other:?}"),
    };
    (reader, frame, payload)
}

#[library_benchmark]
#[bench::bodies_response(args = (SPEND_1IN_2OUT), setup = served)]
fn crypto_bench_levin_bodies_decode(
    (requested, payload): (Vec<[u8; 32]>, Vec<u8>),
) -> (Vec<[u8; 32]>, Vec<u8>, ResponseBodies) {
    let response = black_box(ResponseBodies::decode(black_box(&payload)).expect("the payload"));
    response
        .check_form(&requested)
        .expect("the response answers the request");
    (requested, payload, response)
}

library_benchmark_group!(
    name = levin_bodies_group;
    benchmarks = crypto_bench_levin_frame_read, crypto_bench_levin_bodies_decode
);

main!(library_benchmark_groups = levin_bodies_group);
