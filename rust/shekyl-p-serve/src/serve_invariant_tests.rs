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
//! the next until that write has returned. So it is always at most one
//! chunk ahead of what the requester's side has *accepted*:
//!
//! ```text
//! reads <= floor(body_bytes_accepted / WRITE_CHUNK_BYTES) + 1
//! ```
//!
//! The `+ 1` is the lookahead, and it is real work: the loop has to read
//! a chunk to find out that the write of it is refused. A requester that
//! accepts nothing costs one read, and one that accepts four whole chunks
//! costs five. When the last chunk was accepted in part the bound is
//! `ceil(accepted / chunk)`, the same number. So the cost of a requester
//! that leaves is one chunk past what it took, whatever the shard's size.
//!
//! "Accepted" is the requester's own buffer in the sink tests, where it is
//! exact, and the two kernel buffers between the ends (the persona's send
//! buffer and the requester's receive buffer) over a real socket.
//!
//! The sink tests assert the bound as an equality. The socket tests assert
//! it as an inequality with every term named, which needs the two kernel
//! buffers to be known: left alone, Linux autotunes the persona's send
//! buffer up to `net.ipv4.tcp_wmem`'s maximum (4 MiB by default, larger
//! than a whole shard), and a test that hoped it stayed small would pass
//! or fail on the kernel's mood. So those tests bind the endpoint with its
//! send buffer pinned ([`PServeEndpoint::bind_with_send_buffer`]) and
//! connect with a pinned receive buffer; setting either turns its
//! autotuning off. What the persona can have written that the requester
//! has not read is then at most the two buffers, and
//!
//! ```text
//! accepted <= bytes the requester read + its receive buffer + P's send buffer
//! ```
//!
//! holds whatever the timing, since it is accounting and not a race.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_types::{BlockHeight, SHARD_LENGTH};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    fetch, filler, good_get_shard_0, head_of, render_ok, resolve, write_response, PServeEndpoint,
    Resolved, OWN_HEIGHT, SIGNATURE_ENVELOPE_LEN, WRITE_CHUNK_BYTES,
};
use crate::countersign::{PassKey, PassSigner, SignRefused, TestKeySigner};
use crate::provider::{ProviderError, ShardBody, ShardProvider};
use crate::serve_counters::ServeCounterReader;

/// Shard 0, in memory, counting how often it is opened and how many
/// chunks of it are then yielded.
pub(super) struct CountingProvider {
    bytes: Arc<[u8]>,
    opens: AtomicUsize,
    reads: Arc<AtomicUsize>,
}

impl CountingProvider {
    pub(super) fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bytes: Arc::from(bytes.into_boxed_slice()),
            opens: AtomicUsize::new(0),
            reads: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(super) fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    pub(super) fn reads(&self) -> usize {
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
        Ok(Some(ShardBody::counted(
            Arc::clone(&self.bytes),
            Arc::clone(&self.reads),
        )))
    }
}

/// How a [`CountingSigner`] answers: each is one of the signer-side
/// outcomes the endpoint has a response for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Signs {
    /// Ready, and signs.
    Always,
    /// Refuses its pre-flight: the 503 before any shard byte.
    NotReady,
    /// Ready, then fails to sign after the body: the refusal trailer.
    FailsLate,
    /// Cannot read its own height: the 503, a lookup failure.
    NoHeight,
}

/// The test key, counting the signatures it is asked for.
pub(super) struct CountingSigner {
    key: TestKeySigner,
    signs: Signs,
    asked_to_sign: AtomicUsize,
}

impl CountingSigner {
    pub(super) fn new() -> Arc<Self> {
        Self::that(Signs::Always)
    }

    pub(super) fn that(signs: Signs) -> Arc<Self> {
        Arc::new(Self {
            key: TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)),
            signs,
            asked_to_sign: AtomicUsize::new(0),
        })
    }

    pub(super) fn asked_to_sign(&self) -> usize {
        self.asked_to_sign.load(Ordering::SeqCst)
    }

    pub(super) fn key(&self) -> &TestKeySigner {
        &self.key
    }
}

impl PassKey for CountingSigner {
    fn ready(&self, shard_id: u64, anchor_height: BlockHeight) -> Result<(), SignRefused> {
        if self.signs == Signs::NotReady {
            return Err(SignRefused::new("counting signer: not ready"));
        }
        self.key.ready(shard_id, anchor_height)
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.asked_to_sign.fetch_add(1, Ordering::SeqCst);
        if self.signs == Signs::FailsLate {
            return Err(SignRefused::new("counting signer: fails late"));
        }
        self.key.sign_pass(message)
    }
}

impl PassSigner for CountingSigner {
    fn own_height(&self) -> Option<BlockHeight> {
        if self.signs == Signs::NoHeight {
            return None;
        }
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

/// The largest body a shard can be, to the order the tests here care
/// about: `W` archival bytes (`SHT-Q2`). The real body is `W` plus the
/// overshoot of one transaction and the frame's per-transaction lengths,
/// and a bound that holds at `W` holds there.
fn full_body_bytes() -> usize {
    usize::try_from(SHARD_LENGTH.to_raw()).expect("W fits usize")
}

/// Bytes of a 200 that precede the first body chunk: the head, and nothing
/// else — the loop writes no frame of its own ahead of the body.
fn bytes_ahead_of_the_body(body_bytes: usize) -> usize {
    let content_length = u64::try_from(body_bytes + SIGNATURE_ENVELOPE_LEN).expect("fits");
    render_ok(content_length).len()
}

/// Serve one valid, in-window request for held shard 0 to a requester that
/// accepts `body_bytes_accepted` bytes of the body and then refuses.
/// Returns the chunk reads and the signatures asked for.
async fn serve_to_a_requester_that_accepts(
    chunks_in_body: usize,
    body_bytes_accepted: usize,
) -> (usize, usize, ServeCounterReader) {
    let body_bytes = chunks_in_body * WRITE_CHUNK_BYTES;
    let provider = CountingProvider::new(filler(body_bytes, 0x33));
    let signer = CountingSigner::new();
    let counters = ServeCounterReader::zeroed();
    let writer = counters.writer();

    let resolved = resolve(
        good_get_shard_0().as_bytes(),
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        &writer,
    )
    .await;
    assert!(
        matches!(resolved, Resolved::Held(_)),
        "the fixture must be a valid request for a held shard, or the test counts a refusal"
    );
    let mut requester = Requester {
        taken: 0,
        cap: bytes_ahead_of_the_body(body_bytes) + body_bytes_accepted,
    };
    let outcome = write_response(
        &mut requester,
        resolved,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        &writer,
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
    // fixes the length, and that is all. No chunk is read and nothing is
    // signed, for the smallest body and for a whole shard alike.
    for body_bytes in [1, full_body_bytes()] {
        let provider = CountingProvider::new(filler(body_bytes, 0x21));
        let signer = CountingSigner::new();
        let writer = ServeCounterReader::zeroed().writer();
        let resolved = resolve(
            good_get_shard_0().as_bytes(),
            Arc::clone(&provider) as Arc<dyn ShardProvider>,
            Arc::clone(&signer) as Arc<dyn PassSigner>,
            &writer,
        )
        .await;
        assert!(matches!(resolved, Resolved::Held(_)));
        assert_eq!(provider.opens(), 1, "{body_bytes} bytes: one open");
        assert_eq!(
            provider.reads(),
            0,
            "{body_bytes} bytes: no body byte is read before the head"
        );
        assert_eq!(
            signer.asked_to_sign(),
            0,
            "{body_bytes} bytes: nothing is signed before the head"
        );
    }
}

#[tokio::test]
async fn a_requester_that_takes_only_the_head_costs_one_chunk_read_and_no_signature() {
    // The requester accepts the head and not one body byte. `P` has read
    // the one chunk it then failed to write, and stops.
    let (reads, asked_to_sign, counters) = serve_to_a_requester_that_accepts(8, 0).await;
    assert_eq!(
        reads, 1,
        "one chunk read ahead of the write that was refused"
    );
    assert_eq!(asked_to_sign, 0, "nothing is signed");
    assert_eq!(counters.served_count(), 0);
    assert_eq!(counters.late_sign_failure_count(), 0);
    assert_eq!(
        counters.lookup_failure_count(),
        0,
        "a requester that left is not a store fault"
    );
}

#[tokio::test]
async fn a_requester_that_takes_half_the_body_costs_half_the_reads_and_no_signature() {
    // Half of an eight-chunk body, to the byte: four chunks accepted whole.
    // The fifth is read and refused: reads = floor(accepted / chunk) + 1,
    // and the key is never asked.
    let (reads, asked_to_sign, counters) =
        serve_to_a_requester_that_accepts(8, 4 * WRITE_CHUNK_BYTES).await;
    assert_eq!(reads, 5, "four chunks delivered and one refused, of eight");
    assert_eq!(asked_to_sign, 0, "half a body is not signed for");
    assert_eq!(counters.served_count(), 0);
    assert_eq!(counters.late_sign_failure_count(), 0);
}

#[tokio::test]
async fn a_requester_that_stops_mid_chunk_stops_p_within_that_chunk() {
    // Two chunks and a hundred bytes of a third. The third was read in
    // full, since a chunk is the unit, and nothing after it was:
    // reads = floor(accepted / chunk) + 1 = 3, of eight.
    let accepted = 2 * WRITE_CHUNK_BYTES + 100;
    let (reads, asked_to_sign, _) = serve_to_a_requester_that_accepts(8, accepted).await;
    assert_eq!(reads, accepted / WRITE_CHUNK_BYTES + 1);
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
    let provider = CountingProvider::new(filler(chunks_in_body * WRITE_CHUNK_BYTES, 0x55));
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

/// `SO_SNDBUF` asked of the persona's accepted sockets, and `SO_RCVBUF`
/// asked of the requester's. Small, so that both together are a small
/// fraction of a shard.
const PINNED_BUFFER_BYTES: u32 = 32 * 1024;

/// Linux doubles a requested socket buffer to leave room for bookkeeping
/// (`socket(7)`, `SO_SNDBUF`), so the persona's send buffer holds at most
/// this. The requester's side is read back from its own socket instead.
const SEND_BUFFER_CEILING_BYTES: usize = 2 * PINNED_BUFFER_BYTES as usize;

/// A receive queue may run past its limit by the segment that crossed it,
/// and on loopback one segment can be as large as one chunk. One chunk of
/// slack covers it.
const RECEIVE_OVERSHOOT_CHUNKS: usize = 1;

/// Serve a whole shard over a real socket, with both kernel buffers
/// pinned, to a requester that reads the head and `body_bytes_wanted`
/// more, then closes. Returns the chunk reads once the response has
/// ended, the bound on them, the chunks in the body, and the endpoint
/// and signer for the caller's assertions.
async fn serve_a_shard_to_a_requester_that_reads(
    body_bytes_wanted: usize,
) -> (usize, usize, usize, PServeEndpoint, Arc<CountingSigner>) {
    let body_bytes = full_body_bytes();
    let total_chunks = body_bytes.div_ceil(WRITE_CHUNK_BYTES);
    let provider = CountingProvider::new(filler(body_bytes, 0x44));
    let signer = CountingSigner::new();
    let ep = PServeEndpoint::bind_with_send_buffer(
        Arc::clone(&provider) as Arc<dyn ShardProvider>,
        Arc::clone(&signer) as Arc<dyn PassSigner>,
        PINNED_BUFFER_BYTES,
    )
    .expect("bind");

    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .set_recv_buffer_size(PINNED_BUFFER_BYTES)
        .expect("pin the receive buffer");
    let receive_buffer = socket.recv_buffer_size().expect("read it back") as usize;
    let mut s = socket.connect(ep.addr()).await.expect("connect");
    s.write_all(good_get_shard_0().as_bytes())
        .await
        .expect("write request");

    // Read the head, then exactly as much more as this requester wants.
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let head_len = loop {
        if let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = s.read(&mut buf).await.expect("read head");
        assert!(n > 0, "the server closed before the head");
        seen.extend_from_slice(&buf[..n]);
    };
    assert!(head_of(&seen).starts_with("HTTP/1.1 200 OK"));
    while seen.len() < head_len + body_bytes_wanted {
        let want = (head_len + body_bytes_wanted - seen.len()).min(buf.len());
        let n = s.read(&mut buf[..want]).await.expect("read body");
        assert!(n > 0, "the server closed before the requester did");
        seen.extend_from_slice(&buf[..n]);
    }
    let read_by_requester = seen.len();
    drop(s);

    // The response is over when the serve loop drops the body it was
    // streaming: a definite event. Bounded well under the endpoint's own
    // stall timeout, so a serve that hangs fails here and says so.
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.bodies_open() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the serve loop ends the response once the requester has closed");

    // Everything the persona wrote went somewhere: the requester read it,
    // or it sat in the requester's receive buffer, or in the persona's
    // send buffer. The head is counted as body here, which only loosens
    // the bound.
    let accepted = read_by_requester + receive_buffer + SEND_BUFFER_CEILING_BYTES;
    let bound = accepted / WRITE_CHUNK_BYTES + 1 + RECEIVE_OVERSHOOT_CHUNKS;
    assert!(
        bound < total_chunks,
        "the fixture must leave the bound below the body ({bound} of {total_chunks}), \
         or the test below it asserts nothing"
    );
    (provider.reads(), bound, total_chunks, ep, signer)
}

#[tokio::test]
async fn a_requester_that_closes_after_the_head_costs_a_bounded_read_and_no_signature() {
    // Through the endpoint and a real socket, with the largest body a
    // shard can be. The requester reads the head and closes. The persona
    // has read no more than the two pinned buffers could take, plus the
    // one chunk it is always ahead by, and the key is never asked.
    let (reads, bound, total_chunks, ep, signer) = serve_a_shard_to_a_requester_that_reads(0).await;
    assert!(
        reads > 0,
        "the head was received, so the loop read at least one chunk"
    );
    assert!(
        reads <= bound,
        "{reads} chunks read of {total_chunks}; the buffers allow at most {bound}"
    );
    assert_eq!(signer.asked_to_sign(), 0, "never signed for");
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
}

#[tokio::test]
async fn a_requester_that_reads_half_and_closes_costs_about_half_and_no_signature() {
    // The requester takes half of a whole shard and closes. Left to
    // autotune, the kernel could hold the other half and the persona would
    // finish and sign for a requester that had gone; with both buffers
    // pinned it cannot. The reads stop within the buffers of the half that
    // was read, and the key is never asked.
    let half = full_body_bytes() / 2;
    let (reads, bound, total_chunks, ep, signer) =
        serve_a_shard_to_a_requester_that_reads(half).await;
    assert!(
        reads >= half / WRITE_CHUNK_BYTES,
        "the requester read half, so the persona read at least that"
    );
    assert!(
        reads <= bound,
        "{reads} chunks read of {total_chunks}; half plus the buffers allows at most {bound}"
    );
    assert_eq!(signer.asked_to_sign(), 0, "half a body is not signed for");
    assert_eq!(ep.served_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
}
