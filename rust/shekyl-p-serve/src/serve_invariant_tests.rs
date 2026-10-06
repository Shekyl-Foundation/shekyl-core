// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The abuse invariant the single-pass serve exists for (`BA-Q3`): **`P`
//! does no work that scales with shard size until the requester has
//! received the bytes that work is for.**
//!
//! The endpoint suite proves what a complete response looks like. Nothing
//! there would fail if a later change moved a read, a hash or the hybrid
//! sign back in front of the head, which is how the two-pass serve of
//! 2026-10-04 cost a persona a whole shard read, a digest and a signature
//! for a requester that sent one head and left. Each test here holds one
//! clause of the sentence above, by counting the two things that scale or
//! cost: chunk reads of the body, and calls to `sign_pass`.
//!
//! # The bound, and where it comes from
//!
//! The serve loop reads a chunk, folds it, writes it, and does not read
//! the next until that write has returned. So the chunks it reads are
//! bounded by the bytes the requester's side has *accepted*:
//!
//! ```text
//! reads <= ceil(body_bytes_accepted / WRITE_CHUNK_BYTES)
//! ```
//!
//! with equality when the last accepted chunk was accepted only in part.
//! "Accepted" is the requester's own buffer in the sink tests, where it is
//! exact, and the two kernel buffers between the ends (the persona's send
//! buffer and the requester's receive buffer) over a real socket.
//!
//! The sink tests assert the bound as an equality. The socket test asserts
//! only that the reads stopped short of the body and that nothing was
//! signed: an absolute bound there would have to name the persona's
//! `SO_SNDBUF`, which Linux autotunes up to `net.ipv4.tcp_wmem`'s maximum
//! (4 MiB by default, larger than a whole shard), and pinning it would
//! take a production seam on the listener that this endpoint does not
//! have.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::{leaves_per_segment, ServedFrameHeader, LEAF_BYTES};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{
    fetch, good_get_shard_0, head_of, leaves, render_ok, resolve, write_response, PServeEndpoint,
    Resolved, OWN_HEIGHT, SIGNATURE_ENVELOPE_LEN, WRITE_CHUNK_BYTES,
};
use crate::countersign::{PassKey, PassSigner, SignRefused, TestKeySigner};
use crate::provider::{ProviderError, ShardBody, ShardProvider};

/// Shard 0, in memory, counting how often it is opened and how many
/// chunks of it are then yielded.
struct CountingProvider {
    bytes: Arc<[u8]>,
    opens: AtomicUsize,
    reads: Arc<AtomicUsize>,
}

impl CountingProvider {
    fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bytes: Arc::from(bytes.into_boxed_slice()),
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

    /// Bodies handed out and not yet dropped. Each body holds a clone of
    /// the read counter, so the counter's reference count is the provider
    /// plus one per live body.
    fn bodies_open(&self) -> usize {
        Arc::strong_count(&self.reads) - 1
    }
}

impl ShardProvider for CountingProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if shard_id != 0 {
            return Ok(None);
        }
        Ok(ShardBody::counted(
            Arc::clone(&self.bytes),
            Arc::clone(&self.reads),
        ))
    }
}

/// The test key, counting the signatures it is asked for.
struct CountingSigner {
    key: TestKeySigner,
    asked_to_sign: AtomicUsize,
}

impl CountingSigner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)),
            asked_to_sign: AtomicUsize::new(0),
        })
    }

    fn asked_to_sign(&self) -> usize {
        self.asked_to_sign.load(Ordering::SeqCst)
    }
}

impl PassKey for CountingSigner {
    fn ready(&self, shard_id: u64, anchor_height: BlockHeight) -> Result<(), SignRefused> {
        self.key.ready(shard_id, anchor_height)
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.asked_to_sign.fetch_add(1, Ordering::SeqCst);
        self.key.sign_pass(message)
    }
}

impl PassSigner for CountingSigner {
    fn own_height(&self) -> Option<BlockHeight> {
        self.key.own_height()
    }
}

/// A requester, as a writer: accepts `cap` bytes and then refuses every
/// write, the way a socket does once its peer has gone and the buffers
/// between them are full.
struct Requester {
    taken: usize,
    cap: usize,
}

impl AsyncWrite for Requester {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let room = self.cap - self.taken;
        if room == 0 {
            return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
        }
        let n = buf.len().min(room);
        self.taken += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The endpoint's counters, as a test holds them when it drives `resolve`
/// and `write_response` directly.
#[derive(Default)]
struct Counted {
    served: AtomicU64,
    lookup_failures: AtomicU64,
    sign_failures: AtomicU64,
    late_sign_failures: AtomicU64,
}

/// Bytes of a 200 that precede the first body chunk: the head and the
/// `RF-D4` frame header, for a body of `leaves_in_body`.
fn bytes_ahead_of_the_body(leaves_in_body: usize) -> usize {
    let frame = ServedFrameHeader::for_segment(leaves_in_body).expect("in range");
    render_ok(frame.framed_len() + SIGNATURE_ENVELOPE_LEN as u64).len() + frame.encoded_len()
}

/// Serve one valid, in-window request for held shard 0 to a requester that
/// accepts `body_bytes_accepted` bytes of the body and then refuses.
/// Returns the chunk reads and the signatures asked for.
async fn serve_to_a_requester_that_accepts(
    chunks_in_body: usize,
    body_bytes_accepted: usize,
) -> (usize, usize, Counted) {
    let leaves_in_body = chunks_in_body * WRITE_CHUNK_BYTES / LEAF_BYTES;
    assert_eq!(
        leaves_in_body * LEAF_BYTES,
        chunks_in_body * WRITE_CHUNK_BYTES,
        "the fixture's body is a whole number of chunks"
    );
    let provider = CountingProvider::new(leaves(leaves_in_body, 0x33));
    let signer = CountingSigner::new();
    let counters = Counted::default();

    let resolved = resolve(
        good_get_shard_0().as_bytes(),
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        &counters.lookup_failures,
        &counters.sign_failures,
    )
    .await;
    assert!(
        matches!(resolved, Resolved::Held(_)),
        "the fixture must be a valid request for a held shard, or the test counts a refusal"
    );
    let mut requester = Requester {
        taken: 0,
        cap: bytes_ahead_of_the_body(leaves_in_body) + body_bytes_accepted,
    };
    let outcome = write_response(
        &mut requester,
        resolved,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        &counters.served,
        &counters.lookup_failures,
        &counters.late_sign_failures,
    )
    .await;
    assert!(outcome.is_err(), "the refused write ends the response");
    assert_eq!(
        requester.taken, requester.cap,
        "the requester accepted exactly its buffer"
    );
    (provider.reads(), signer.asked_to_sign(), counters)
}

#[tokio::test]
async fn nothing_that_scales_with_the_shard_happens_before_the_head() {
    // Everything `P` does before its first response byte, for a valid
    // in-window request for a held shard: the shard is opened once, which
    // fixes the frame, and that is all. No chunk is read and nothing is
    // signed, for the smallest body and for a whole segment alike.
    for leaves_in_body in [1, leaves_per_segment()] {
        let provider = CountingProvider::new(leaves(leaves_in_body, 0x21));
        let signer = CountingSigner::new();
        let counters = Counted::default();
        let resolved = resolve(
            good_get_shard_0().as_bytes(),
            Arc::clone(&provider) as Arc<dyn ShardProvider>,
            Arc::clone(&signer) as Arc<dyn PassSigner>,
            &counters.lookup_failures,
            &counters.sign_failures,
        )
        .await;
        assert!(matches!(resolved, Resolved::Held(_)));
        assert_eq!(provider.opens(), 1, "{leaves_in_body} leaves: one open");
        assert_eq!(
            provider.reads(),
            0,
            "{leaves_in_body} leaves: no body byte is read before the head"
        );
        assert_eq!(
            signer.asked_to_sign(),
            0,
            "{leaves_in_body} leaves: nothing is signed before the head"
        );
    }
}

#[tokio::test]
async fn a_requester_that_takes_only_the_head_costs_one_chunk_read_and_no_signature() {
    // The requester accepts the head and the frame header and not one body
    // byte. `P` has read the one chunk it then failed to write, and stops.
    let (reads, asked_to_sign, counters) = serve_to_a_requester_that_accepts(8, 0).await;
    assert_eq!(
        reads, 1,
        "one chunk read ahead of the write that was refused"
    );
    assert_eq!(asked_to_sign, 0, "nothing is signed");
    assert_eq!(counters.served.load(Ordering::Relaxed), 0);
    assert_eq!(counters.late_sign_failures.load(Ordering::Relaxed), 0);
    assert_eq!(
        counters.lookup_failures.load(Ordering::Relaxed),
        0,
        "a requester that left is not a store fault"
    );
}

#[tokio::test]
async fn a_requester_that_takes_half_the_body_costs_half_the_reads_and_no_signature() {
    // Half of an eight-chunk body, to the byte: four chunks accepted whole.
    // The fifth is read and refused. reads = ceil(accepted / chunk) + 1 at
    // an exact chunk boundary, and the key is never asked.
    let (reads, asked_to_sign, counters) =
        serve_to_a_requester_that_accepts(8, 4 * WRITE_CHUNK_BYTES).await;
    assert_eq!(reads, 5, "four chunks delivered and one refused, of eight");
    assert_eq!(asked_to_sign, 0, "half a body is not signed for");
    assert_eq!(counters.served.load(Ordering::Relaxed), 0);
    assert_eq!(counters.late_sign_failures.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_requester_that_stops_mid_chunk_stops_p_within_that_chunk() {
    // Two chunks and a hundred bytes of a third. The third was read in
    // full, since a chunk is the unit, and nothing after it was:
    // reads = ceil(accepted / chunk) = 3, of eight.
    let accepted = 2 * WRITE_CHUNK_BYTES + 100;
    let (reads, asked_to_sign, _) = serve_to_a_requester_that_accepts(8, accepted).await;
    assert_eq!(reads, accepted.div_ceil(WRITE_CHUNK_BYTES));
    assert_eq!(reads, 3);
    assert_eq!(asked_to_sign, 0);
}

#[tokio::test]
async fn a_requester_that_takes_everything_costs_every_chunk_and_one_signature() {
    // The control for the tests above: the same counters on a response
    // that completes. Every chunk is yielded once, the read that finds the
    // end is not counted as one, and the key is asked exactly once, after
    // them. Without this, a counter that never moved would pass every
    // "no more than" above.
    let chunks_in_body = 8;
    let leaves_in_body = chunks_in_body * WRITE_CHUNK_BYTES / LEAF_BYTES;
    let provider = CountingProvider::new(leaves(leaves_in_body, 0x55));
    let signer = CountingSigner::new();
    let ep = PServeEndpoint::bind(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind");

    let r = fetch(ep.addr(), "/shard/0").await;
    assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(provider.opens(), 1);
    assert_eq!(provider.reads(), chunks_in_body, "every chunk, once");
    assert_eq!(signer.asked_to_sign(), 1, "one signature, after the body");
    assert_eq!(ep.served_count(), 1);
    assert_eq!(
        provider.bodies_open(),
        0,
        "the body is dropped with the response"
    );
}

#[tokio::test]
async fn a_requester_that_closes_after_the_head_is_never_signed_for() {
    // The same clause through the endpoint and a real socket, with the
    // largest body a shard can be. The requester reads the head and
    // closes. The persona's writes fail once the close reaches it, long
    // before a whole segment is out, and the key is never asked. How many
    // chunks went into the kernel's buffers first is the kernel's (see the
    // module docs); the sink tests pin the mechanism to the byte.
    let leaves_in_body = leaves_per_segment();
    let total_chunks = (leaves_in_body * LEAF_BYTES).div_ceil(WRITE_CHUNK_BYTES);
    let provider = CountingProvider::new(leaves(leaves_in_body, 0x44));
    let signer = CountingSigner::new();
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

    // The response is over when the serve loop drops the body it was
    // streaming: a definite event, not a guess that the reads have gone
    // quiet. Bounded well under the endpoint's own stall timeout, so a
    // serve that hangs fails here and says so.
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.bodies_open() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the serve loop ends the response once the requester has closed");
    let settled = provider.reads();
    assert!(
        settled > 0,
        "the head was received, so the loop read at least the chunk it then failed to write"
    );
    assert!(
        settled < total_chunks,
        "{settled} of {total_chunks} chunks read: the close must stop the body short"
    );
    assert_eq!(signer.asked_to_sign(), 0, "never signed for");
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
}
