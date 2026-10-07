// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `BA-T3` gate measures [`serve_one_in_memory`], not the endpoint: a
//! composition of the endpoint's own steps on one thread, because
//! Callgrind cannot count a response whose steps run on a thread pool.
//! That makes the composition a second arrangement of the same steps, and
//! a gate over a second arrangement is only worth what holds the two
//! together.
//!
//! Bytes alone do not. A serve that read every chunk twice, or signed
//! twice, would put the same bytes on the wire, and it is exactly a
//! change in how often the body is read, hashed or signed that the gate
//! exists to see. So for every outcome the endpoint has a response for,
//! these tests hold the composition to the live endpoint on both: the
//! bytes, and the number of shard opens, chunk reads and signatures it
//! took to produce them.
//!
//! One outcome is not held here: a 200 that ends short because the store
//! failed mid-body or yielded a body that is not its frame's length. No
//! fixture in this crate can build such a body, since an in-memory body
//! derives its frame from its own length.

use std::sync::Arc;

use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_curve_tree::{leaves_per_segment, LEAF_BYTES};
use shekyl_types::BlockHeight;

use super::invariant::{CountingProvider, CountingSigner, Signs};
use super::{
    good_get_shard_0, good_header, header_at, header_line, is_refusal_trailer, leaves,
    parse_served, prehead_in_memory, read_and_fold_in_memory, request_raw, serve_one_in_memory,
    InMemoryServe, PServeEndpoint, ANCHOR_HASH, IN_GATE_ANCHOR, NONCE, OWN_HEIGHT,
    SIGNATURE_ENVELOPE_LEN, WRITE_CHUNK_BYTES,
};
use crate::countersign::PassSigner;
use crate::provider::ShardProvider;

/// What it took to answer one request: the outcome's bytes, and the work.
#[derive(Debug, PartialEq, Eq)]
struct Cost {
    opens: usize,
    reads: usize,
    signatures: usize,
}

/// One request through the live endpoint, with fresh counters.
async fn over_the_wire(
    body: &[u8],
    signs: Signs,
    head: &str,
) -> (Vec<u8>, Cost, Arc<CountingSigner>) {
    let provider = CountingProvider::new(body.to_vec());
    let signer = CountingSigner::that(signs);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");
    let response = request_raw(ep.addr(), head).await;
    let cost = Cost {
        opens: provider.opens(),
        reads: provider.reads(),
        signatures: signer.asked_to_sign(),
    };
    (response, cost, signer)
}

/// The same request through the bench composition, with fresh counters.
fn in_memory(
    body: &[u8],
    signs: Signs,
    head: &str,
) -> (Vec<u8>, Cost, InMemoryServe, Arc<CountingSigner>) {
    let provider = CountingProvider::new(body.to_vec());
    let signer = CountingSigner::that(signs);
    let mut out = Vec::new();
    let outcome = serve_one_in_memory(&*provider, &*signer, head.as_bytes(), &mut out);
    let cost = Cost {
        opens: provider.opens(),
        reads: provider.reads(),
        signatures: signer.asked_to_sign(),
    };
    (out, cost, outcome, signer)
}

fn head_for(path: &str, anchor: u64) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nhost: x\r\n{}\r\n",
        header_line(&header_at(anchor))
    )
}

#[tokio::test]
async fn a_served_response_is_the_same_bytes_for_the_same_work() {
    // Three chunks and a part, so the read loop turns more than once and
    // ends on a short chunk.
    let leaves_in_body = (3 * WRITE_CHUNK_BYTES + WRITE_CHUNK_BYTES / 2) / LEAF_BYTES;
    let body = leaves(leaves_in_body, 0x11);
    let chunks = body.len().div_ceil(WRITE_CHUNK_BYTES);
    let head = good_get_shard_0();

    let (wire, wire_cost, wire_signer) = over_the_wire(&body, Signs::Always, &head).await;
    let (memory, memory_cost, outcome, memory_signer) = in_memory(&body, Signs::Always, &head);

    assert_eq!(outcome, InMemoryServe::Served);
    assert_eq!(
        wire_cost,
        Cost {
            opens: 1,
            reads: chunks,
            signatures: 1
        },
        "the endpoint: one open, every chunk once, one signature"
    );
    assert_eq!(
        memory_cost, wire_cost,
        "the composition took the same opens, chunk reads and signatures"
    );
    // The signature is hedged, so the two envelopes differ; everything
    // ahead of them is identical, and each envelope verifies.
    assert_eq!(wire.len(), memory.len());
    let cut = wire.len() - SIGNATURE_ENVELOPE_LEN;
    assert_eq!(
        wire[..cut],
        memory[..cut],
        "head, frame and body are identical"
    );
    for (response, signer) in [(&wire, &wire_signer), (&memory, &memory_signer)] {
        let served = parse_served(response);
        verify_pass_transcript(
            signer.key().public_key(),
            &NONCE,
            BlockHeight::from_raw(IN_GATE_ANCHOR),
            &ANCHOR_HASH,
            0,
            &pass_delivery_digest(&NONCE, &served.framed),
            &served.signature,
        )
        .expect("each envelope verifies under its key");
    }
}

#[tokio::test]
async fn every_refusal_is_the_same_bytes_for_the_same_work() {
    let body = leaves(9, 0x40);
    let cases: [(&str, Signs, String, InMemoryServe, Cost); 5] = [
        (
            "an unknown route",
            Signs::Always,
            format!(
                "GET /nope HTTP/1.1\r\nhost: x\r\n{}\r\n",
                header_line(&good_header())
            ),
            InMemoryServe::BadRequest,
            Cost {
                opens: 0,
                reads: 0,
                signatures: 0,
            },
        ),
        (
            "an anchor outside the gate",
            Signs::Always,
            head_for("/shard/0", OWN_HEIGHT),
            InMemoryServe::BadRequest,
            Cost {
                opens: 0,
                reads: 0,
                signatures: 0,
            },
        ),
        (
            "a shard that is not held",
            Signs::Always,
            head_for("/shard/9", IN_GATE_ANCHOR),
            InMemoryServe::NotHeld,
            Cost {
                opens: 1,
                reads: 0,
                signatures: 0,
            },
        ),
        (
            "a key that is not ready",
            Signs::NotReady,
            good_get_shard_0(),
            InMemoryServe::Unavailable,
            Cost {
                opens: 1,
                reads: 0,
                signatures: 0,
            },
        ),
        (
            "a height that cannot be read",
            Signs::NoHeight,
            good_get_shard_0(),
            InMemoryServe::Unavailable,
            Cost {
                opens: 0,
                reads: 0,
                signatures: 0,
            },
        ),
    ];
    for (what, signs, head, expected, expected_cost) in cases {
        let (wire, wire_cost, _) = over_the_wire(&body, signs, &head).await;
        let (memory, memory_cost, outcome, _) = in_memory(&body, signs, &head);
        assert_eq!(outcome, expected, "{what}");
        assert_eq!(wire_cost, expected_cost, "{what}: the endpoint's work");
        assert_eq!(memory_cost, wire_cost, "{what}: the same work");
        assert_eq!(memory, wire, "{what}: the same bytes");
    }
}

#[tokio::test]
async fn a_late_refusal_is_the_same_trailer_for_the_same_work() {
    let body = leaves(9, 0x40);
    let head = good_get_shard_0();
    let (wire, wire_cost, _) = over_the_wire(&body, Signs::FailsLate, &head).await;
    let (memory, memory_cost, outcome, _) = in_memory(&body, Signs::FailsLate, &head);
    assert_eq!(outcome, InMemoryServe::Unsigned);
    assert_eq!(
        wire_cost,
        Cost {
            opens: 1,
            reads: 1,
            signatures: 1
        }
    );
    assert_eq!(memory_cost, wire_cost);
    assert_eq!(memory, wire, "no hedged bytes here: identical to the last");
    assert!(is_refusal_trailer(
        &wire[wire.len() - SIGNATURE_ENVELOPE_LEN..]
    ));
}

#[tokio::test]
async fn the_pre_head_arm_is_the_head_of_the_response_and_reads_no_body() {
    // The abuse arm. What it renders is byte for byte what the endpoint
    // sends ahead of the first body chunk, and producing it opens the
    // shard once, reads no chunk and signs nothing — for the smallest
    // body and for a whole segment. That is the size-independence the
    // gate's two pre-head cells are compared for: Callgrind's counts are
    // not visible to the process being counted, so the bench cannot
    // assert it, and this does.
    for leaves_in_body in [1, leaves_per_segment()] {
        let body = leaves(leaves_in_body, 0x21);
        let head = good_get_shard_0();
        let provider = CountingProvider::new(body.clone());
        let signer = CountingSigner::new();
        let mut ahead = Vec::new();
        assert!(prehead_in_memory(
            &*provider,
            &*signer,
            head.as_bytes(),
            &mut ahead
        ));
        assert_eq!(provider.opens(), 1, "{leaves_in_body} leaves");
        assert_eq!(provider.reads(), 0, "{leaves_in_body} leaves: no body read");
        assert_eq!(signer.asked_to_sign(), 0, "{leaves_in_body} leaves");

        let (wire, _, _) = over_the_wire(&body, Signs::Always, &head).await;
        assert_eq!(
            wire[..ahead.len()],
            ahead[..],
            "{leaves_in_body} leaves: the endpoint's first bytes"
        );
        assert_eq!(
            wire.len(),
            ahead.len() + body.len() + SIGNATURE_ENVELOPE_LEN,
            "{leaves_in_body} leaves: and the body and envelope are all that follow"
        );
    }
    // A request the endpoint refuses has no 200 head to be ready.
    let provider = CountingProvider::new(leaves(1, 0x21));
    let signer = CountingSigner::that(Signs::NotReady);
    let mut ahead = Vec::new();
    assert!(!prehead_in_memory(
        &*provider,
        &*signer,
        good_get_shard_0().as_bytes(),
        &mut ahead
    ));
    assert!(ahead.is_empty());
}

#[test]
fn the_read_and_fold_arm_is_the_delivery_digest_at_the_serve_chunk_size() {
    // The arm BA-T3 sets beside the one-shot digest. It must be the same
    // digest, of the same bytes, reached by reading at the size the serve
    // loop reads at; otherwise the difference between the two cells is
    // not the cost of interleaving.
    let leaves_in_body = (2 * WRITE_CHUNK_BYTES + WRITE_CHUNK_BYTES / 2) / LEAF_BYTES;
    let body = leaves(leaves_in_body, 0x66);
    let provider = CountingProvider::new(body.clone());
    let digest = read_and_fold_in_memory(&*provider, 0, &NONCE).expect("held, and whole");

    let mut ahead = Vec::new();
    assert!(prehead_in_memory(
        &*CountingProvider::new(body.clone()),
        &*CountingSigner::new(),
        good_get_shard_0().as_bytes(),
        &mut ahead
    ));
    let frame_at = ahead
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head")
        + 4;
    let mut framed = ahead[frame_at..].to_vec();
    framed.extend_from_slice(&body);
    assert_eq!(digest, pass_delivery_digest(&NONCE, &framed));
    assert_eq!(provider.opens(), 1);
    assert_eq!(provider.reads(), body.len().div_ceil(WRITE_CHUNK_BYTES));
    assert!(read_and_fold_in_memory(&*provider, 9, &NONCE).is_none());
}
