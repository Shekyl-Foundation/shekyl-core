// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seal and the `SF-D8` invariant (amended 2026-10-06): the
//! countersignature is the response's last bytes, over exactly the bytes
//! written, and `P` does no work that scales with shard size until the
//! requester has received the bytes that work is for. Each test here holds
//! one clause of that sentence. Split out of the endpoint suite so that
//! file stays under a thousand lines.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_archival_retention::{pass_delivery_digest, verify_pass_transcript};
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::{leaves_per_segment, ServedFrameHeader, LEAF_BYTES};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    bind, fetch, good_get_shard_0, head_of, leaves, render_not_found, respond, Counters,
    FixtureProvider, PServeEndpoint, PassKey, PassSigner, SignRefused, TestKeySigner, ANCHOR_HASH,
    IN_GATE_ANCHOR, NONCE, OWN_HEIGHT, SIGNATURE_ENVELOPE_LEN, WRITE_CHUNK_BYTES,
};
use crate::provider::{ProviderError, ShardBody, ShardProvider};

/// Provider that hands out one scripted body for shard 0 — a header of
/// `declared_leaves` over `bytes` of any length, with a read that may fail
/// — and counts how often it was asked to open a shard and how many chunks
/// the loop then read. The faults a conforming store cannot produce, built
/// by wrapper (rule 50).
struct ScriptedProvider {
    header: ServedFrameHeader,
    bytes: Arc<[u8]>,
    fail_at_read: Option<usize>,
    opens: AtomicUsize,
    reads: Arc<AtomicUsize>,
}

impl ScriptedProvider {
    fn new(declared_leaves: usize, bytes: Vec<u8>, fail_at_read: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            header: ServedFrameHeader::for_segment(declared_leaves).expect("in range"),
            bytes: Arc::from(bytes.into_boxed_slice()),
            fail_at_read,
            opens: AtomicUsize::new(0),
            reads: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl ShardProvider for ScriptedProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if shard_id != 0 {
            return Ok(None);
        }
        Ok(Some(ShardBody::scripted(
            self.header,
            Arc::clone(&self.bytes),
            Arc::clone(&self.reads),
            self.fail_at_read,
        )))
    }
}

/// A signer over the test key that answers its pre-flight as told, counts
/// the signatures it is asked for, and can fail them.
struct Scripted {
    key: Arc<TestKeySigner>,
    ready: bool,
    signs: bool,
    asked_to_sign: AtomicUsize,
}

impl Scripted {
    fn new(ready: bool, signs: bool) -> Arc<Self> {
        Arc::new(Self {
            key: Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT))),
            ready,
            signs,
            asked_to_sign: AtomicUsize::new(0),
        })
    }

    fn asked_to_sign(&self) -> usize {
        self.asked_to_sign.load(Ordering::SeqCst)
    }
}

impl PassKey for Scripted {
    fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> {
        if self.ready {
            Ok(())
        } else {
            Err(SignRefused::new("scripted: not ready"))
        }
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.asked_to_sign.fetch_add(1, Ordering::SeqCst);
        if self.signs {
            self.key.sign_pass(message)
        } else {
            Err(SignRefused::new("scripted: signing fault"))
        }
    }
}

impl PassSigner for Scripted {
    fn own_height(&self) -> Option<BlockHeight> {
        self.key.own_height()
    }
}

/// A requester's socket buffer, as a writer: takes `cap` bytes and then
/// refuses every write, the way a socket whose peer has stopped reading
/// does once the buffers are full and it has been closed.
struct Sink {
    taken: Vec<u8>,
    cap: usize,
}

impl AsyncWrite for Sink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let room = self.cap.saturating_sub(self.taken.len());
        if room == 0 {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
        }
        let n = buf.len().min(room);
        self.taken.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Byte offset of the first body byte: just past the head's blank line.
fn body_start(response: &[u8]) -> usize {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head")
        + 4
}

/// The 200 head, rendered for a body of `declared_leaves`, without the
/// frame header: what the response head of a served `/shard/0` is.
fn head_len_for(declared_leaves: usize) -> usize {
    let frame = ServedFrameHeader::for_segment(declared_leaves).expect("in range");
    let content_length = frame.framed_len() + SIGNATURE_ENVELOPE_LEN as u64;
    super::render_ok(content_length).len()
}

#[tokio::test]
async fn the_countersignature_is_released_only_after_the_whole_frame() {
    // The signature is released last. It is exactly the response's last
    // bytes, and no copy of it appears anywhere ahead of them — so every
    // proper prefix of the response, which is all a reader that stops early
    // can have, is without it.
    let payload = leaves(9, 0x40);
    let (ep, signer) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let r = fetch(ep.addr(), "/shard/0").await;

    let end = body_start(&r);
    let (before, sealed) = r.split_at(r.len() - SIGNATURE_ENVELOPE_LEN);
    let signature =
        HybridSignature::from_canonical_bytes(sealed).expect("the last bytes are the signature");
    verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &pass_delivery_digest(&NONCE, &before[end..]),
        &signature,
    )
    .expect("the closing signature covers this request and the bytes ahead of it");

    // The first body bytes are the frame, not a signature.
    let mut framed = &before[end..];
    let frame = ServedFrameHeader::read(&mut framed).expect("the body opens with the frame");
    assert_eq!(frame.segment_bytes(), payload.len() as u64);
    assert_eq!(framed, &payload[..], "frame header, then the whole segment");

    // No earlier copy: a prefix reader never sees the signature.
    assert!(
        !before.windows(SIGNATURE_ENVELOPE_LEN).any(|w| w == sealed),
        "the signature must not appear ahead of the frame it seals"
    );
}

#[tokio::test]
async fn a_requester_that_stops_taking_bytes_stops_p_within_one_chunk_and_nothing_is_signed() {
    // The invariant's second half, at its exact mechanism: the response is
    // written to a buffer that takes the head, two whole chunks and part
    // of a third, then refuses. The loop reads one chunk, folds it, writes
    // it, and does not read the next until the write has returned — so it
    // reads exactly three chunks of the eight, and the key is never asked.
    let chunks = 8;
    let leaves_in_body = chunks * WRITE_CHUNK_BYTES / LEAF_BYTES;
    let body = leaves(leaves_in_body, 0x33);
    let provider = ScriptedProvider::new(leaves_in_body, body, None);
    let signer = Scripted::new(true, true);
    let frame_len = ServedFrameHeader::for_segment(leaves_in_body)
        .expect("in range")
        .encoded_len();
    let cap = head_len_for(leaves_in_body) + frame_len + 2 * WRITE_CHUNK_BYTES + 100;
    let mut sink = Sink {
        taken: Vec::new(),
        cap,
    };
    let counters = Counters::default();

    let outcome = respond(
        &mut sink,
        good_get_shard_0().as_bytes(),
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        &counters,
    )
    .await;

    assert!(
        outcome.is_err(),
        "the write past the buffer fails the response"
    );
    assert_eq!(
        sink.taken.len(),
        cap,
        "the requester took exactly its buffer"
    );
    assert!(head_of(&sink.taken).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(
        provider.reads(),
        3,
        "two chunks taken whole, one partly: three reads, not eight"
    );
    assert_eq!(
        signer.asked_to_sign(),
        0,
        "nothing is signed for a requester that stopped"
    );
    assert_eq!(counters.served.load(Ordering::Relaxed), 0);
    assert_eq!(
        counters.lookup_failures.load(Ordering::Relaxed),
        0,
        "a requester that stops is not a store fault"
    );
    assert_eq!(counters.late_sign_failures.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_requester_that_disconnects_after_the_head_is_never_signed_for() {
    // The same clause over a real socket, with the largest body a shard
    // can be: the requester reads the head and closes. Loopback buffers
    // hold a fraction of a segment, so the server's writes fail long
    // before the body is out, and the key is never asked. The exact chunk
    // count is the kernel's; the sink test above pins the mechanism.
    let leaves_in_body = leaves_per_segment();
    let total_chunks = (leaves_in_body * LEAF_BYTES).div_ceil(WRITE_CHUNK_BYTES);
    let provider = ScriptedProvider::new(leaves_in_body, leaves(leaves_in_body, 0x44), None);
    let signer = Scripted::new(true, true);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(good_get_shard_0().as_bytes())
        .await
        .expect("write request");
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).await.expect("read head");
        assert!(n > 0, "the server closed before the head");
        seen.extend_from_slice(&buf[..n]);
    }
    assert!(head_of(&seen).starts_with("HTTP/1.1 200 OK"));
    drop(s);

    // The server's writes fail once the close reaches it; wait for the
    // chunk reads to stop moving, bounded.
    let settled = tokio::time::timeout(Duration::from_secs(10), async {
        let mut last = provider.reads();
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = provider.reads();
            if now == last && now > 0 {
                return now;
            }
            last = now;
        }
    })
    .await
    .expect("the chunk reads settle");
    assert!(
        settled < total_chunks,
        "{settled} of {total_chunks} chunks read: the disconnect must stop the body short"
    );
    assert_eq!(signer.asked_to_sign(), 0, "never signed for");
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
}

#[tokio::test]
async fn a_key_that_is_not_ready_is_the_shared_404_with_no_body_read() {
    // The invariant's first half: before the head, constant work only. A
    // key that refuses its pre-flight gets the shard opened — the same
    // lookup an unknown shard costs — and not one chunk read.
    let provider = ScriptedProvider::new(9, leaves(9, 0x40), None);
    let signer = Scripted::new(false, true);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(
        provider.opens(),
        1,
        "the shard was opened, which fixes the cost"
    );
    assert_eq!(
        provider.reads(),
        0,
        "and no body byte was read for a key that is not ready"
    );
    assert_eq!(signer.asked_to_sign(), 0);
    assert_eq!(
        ep.sign_failure_count(),
        1,
        "the pre-flight refusal is the sign-failure bucket"
    );
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);

    // An unknown shard costs the same open and is the same 404, uncounted.
    let miss = fetch(ep.addr(), "/shard/9").await;
    assert_eq!(miss, r);
    assert_eq!(provider.opens(), 2);
    assert_eq!(provider.reads(), 0);
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn a_body_shorter_than_its_frame_ends_without_a_signature() {
    // The store declares nine leaves and yields eight. The head committed
    // to nine; the body ends; the fold is short of the frame, so there is
    // no digest to sign and the response stops. A lookup failure, since
    // the store did this.
    let provider = ScriptedProvider::new(9, leaves(8, 0x40), None);
    let signer = Scripted::new(true, true);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    let head = head_of(&r);
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    let frame = ServedFrameHeader::for_segment(9).expect("in range");
    assert!(head.contains(&format!(
        "content-length: {}",
        frame.framed_len() + SIGNATURE_ENVELOPE_LEN as u64
    )));
    let body = &r[body_start(&r)..];
    assert_eq!(
        body.len(),
        frame.encoded_len() + 8 * LEAF_BYTES,
        "the frame header and the eight leaves the store had, then nothing"
    );
    assert_eq!(
        signer.asked_to_sign(),
        0,
        "a short body is not a prefix someone may sign"
    );
    assert_eq!(ep.lookup_failure_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn a_body_longer_than_its_frame_ends_at_the_frame_without_a_signature() {
    // The store declares exactly one chunk of leaves and yields one more
    // leaf. The first chunk fills the frame and goes out; the next byte is
    // past it, so it is neither folded nor written, and the response ends
    // at the frame with no envelope.
    let declared = WRITE_CHUNK_BYTES / LEAF_BYTES;
    let provider = ScriptedProvider::new(declared, leaves(declared + 1, 0x40), None);
    let signer = Scripted::new(true, true);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    let frame = ServedFrameHeader::for_segment(declared).expect("in range");
    let body = &r[body_start(&r)..];
    assert_eq!(
        body.len() as u64,
        frame.framed_len(),
        "exactly the frame: the byte past it was not written"
    );
    assert_eq!(
        provider.reads(),
        2,
        "the read that produced the extra leaf is the last"
    );
    assert_eq!(signer.asked_to_sign(), 0);
    assert_eq!(ep.lookup_failure_count(), 1);
    assert_eq!(ep.late_sign_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn a_store_fault_after_the_head_ends_the_response_unsigned() {
    // Three chunks declared; the second read fails. One chunk is out, the
    // response ends there, and the key is never asked.
    let leaves_in_body = 3 * WRITE_CHUNK_BYTES / LEAF_BYTES;
    let provider = ScriptedProvider::new(leaves_in_body, leaves(leaves_in_body, 0x40), Some(2));
    let signer = Scripted::new(true, true);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    let frame = ServedFrameHeader::for_segment(leaves_in_body).expect("in range");
    let body = &r[body_start(&r)..];
    assert_eq!(
        body.len(),
        frame.encoded_len() + WRITE_CHUNK_BYTES,
        "the frame header and the one chunk read before the fault"
    );
    assert_eq!(signer.asked_to_sign(), 0);
    assert_eq!(ep.lookup_failure_count(), 1);
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn a_key_that_fails_after_the_body_yields_a_truncated_200_counted_apart() {
    // The cost the ruling accepts: the key passed its pre-flight, the
    // whole body went out, and the signature failed. The head is already
    // out, so this is a 200 short of its envelope by exactly one
    // signature — and it lands in its own counter, not the 404 bucket.
    let provider = ScriptedProvider::new(9, leaves(9, 0x40), None);
    let signer = Scripted::new(true, false);
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    let frame = ServedFrameHeader::for_segment(9).expect("in range");
    let body = &r[body_start(&r)..];
    assert_eq!(
        body.len() as u64,
        frame.framed_len(),
        "the whole frame, then no envelope"
    );
    assert_eq!(signer.asked_to_sign(), 1, "asked once, after the body");
    assert_eq!(ep.late_sign_failure_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0, "not a pre-flight refusal");
    assert_eq!(ep.lookup_failure_count(), 0, "not a store fault");
    assert_eq!(ep.served_count(), 0);
}
