// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Endpoint tests for [`crate::serve`]. Lives beside the production loop so
//! the file that answers the wire stays under a thousand lines; private
//! items remain visible via `#[path]` from `serve.rs`.

use super::*;
use crate::provider::{ProviderError, ShardBody};
use shekyl_curve_tree::{ServedFrameHeader, LEAF_BYTES};

/// In-memory provider: the loop's wire behaviour, storeless.
struct FixtureProvider {
    shards: std::collections::HashMap<u64, Arc<[u8]>>,
}

impl FixtureProvider {
    /// Every fixture payload is asserted servable **here**, at
    /// construction. `ShardBody::flat` returns `None` for anything it
    /// cannot frame, so without this a bad fixture would arrive as a 404
    /// and read as a routing bug — the failure would be real but would
    /// name the wrong thing.
    ///
    /// Two constraints, one authority each. The leaf-multiple check is
    /// spelled out because its message can name the leaf width; the
    /// bound check goes through [`ServedFrameHeader::for_segment`] — the
    /// same call the production path makes — so this guard cannot drift
    /// from `flat`'s actual acceptance rule. (Its first version did
    /// exactly that: it asserted the multiple and silently let an
    /// oversized fixture fall through to the 404 it claimed to prevent.)
    fn new(shards: impl IntoIterator<Item = (u64, Vec<u8>)>) -> Arc<Self> {
        Arc::new(Self {
            shards: shards
                .into_iter()
                .map(|(id, bytes)| {
                    assert!(
                        bytes.len().is_multiple_of(LEAF_BYTES),
                        "fixture for shard {id} is {} bytes, not a whole number of \
                         {LEAF_BYTES}-byte leaves — a served body is a leaf array",
                        bytes.len()
                    );
                    if let Err(e) = ServedFrameHeader::for_segment(bytes.len() / LEAF_BYTES) {
                        panic!("fixture for shard {id} is not servable: {e}");
                    }
                    (id, Arc::from(bytes.into_boxed_slice()))
                })
                .collect(),
        })
    }
}

/// The guards above demonstrated firing — a guard that has never fired is
/// indistinguishable from one that cannot (the defect its first version
/// had, caught in review: the oversized case fell through silently).
#[test]
#[should_panic(expected = "not servable")]
fn an_oversized_fixture_fails_at_construction_not_as_a_404() {
    let leaves = shekyl_curve_tree::leaves_per_segment() + 1;
    FixtureProvider::new([(0, vec![0u8; leaves * LEAF_BYTES])]);
}

#[test]
#[should_panic(expected = "not a whole number")]
fn a_ragged_fixture_fails_at_construction_not_as_a_404() {
    FixtureProvider::new([(0, vec![0u8; LEAF_BYTES - 1])]);
}

impl ShardProvider for FixtureProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        Ok(self
            .shards
            .get(&shard_id)
            .cloned()
            .and_then(ShardBody::flat))
    }
}

/// `n` leaves of distinguishable filler.
fn leaves(n: usize, seed: u8) -> Vec<u8> {
    (0..n * LEAF_BYTES)
        .map(|i| (u8::try_from(i % 251).expect("modulus is under 256")).wrapping_add(seed))
        .collect()
}

/// Split a 200 response into (head, frame header, payload).
fn parse_served(response: &[u8]) -> (String, ServedFrameHeader, Vec<u8>) {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    let head = String::from_utf8_lossy(&response[..end]).to_string();
    let mut body = &response[end + 4..];
    let frame = ServedFrameHeader::read(&mut body).expect("served body carries a frame header");
    (head, frame, body.to_vec())
}

/// Provider whose every lookup fails — the store-failure arm.
struct FailingProvider;

impl ShardProvider for FailingProvider {
    fn shard_bytes(&self, _shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        Err(ProviderError::other("synthetic store failure"))
    }
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

fn head_of(response: &[u8]) -> String {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    String::from_utf8_lossy(&response[..end]).to_string()
}

fn header_names(head: &str) -> Vec<String> {
    head.lines()
        .skip(1)
        .filter(|l| !l.is_empty())
        .map(|l| l.split(':').next().unwrap_or_default().to_ascii_lowercase())
        .collect()
}

#[tokio::test]
async fn binds_loopback_only() {
    // A wildcard or routable bind would make the endpoint reachable
    // without the rendezvous and attributable to the host's IP.
    let ep = PServeEndpoint::bind(FixtureProvider::new([]))
        .await
        .expect("bind");
    assert!(ep.addr().ip().is_loopback());
    assert_ne!(ep.addr().port(), 0, "an ephemeral port was actually bound");
}

#[tokio::test]
async fn serves_each_shard_by_its_own_id() {
    // The capability the spike lacked: the id in the route selects the
    // shard. Two ids must return their own bytes, not a shared buffer.
    let a: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let b: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
    let ep = PServeEndpoint::bind(FixtureProvider::new([(7, a.clone()), (9, b.clone())]))
        .await
        .expect("bind");

    let ra = fetch(ep.addr(), "/x-provisional/v0/shard/7").await;
    assert!(head_of(&ra).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(&ra[ra.len() - a.len()..], &a[..], "shard 7 serves a-bytes");

    let rb = fetch(ep.addr(), "/x-provisional/v0/shard/9").await;
    assert_eq!(&rb[rb.len() - b.len()..], &b[..], "shard 9 serves b-bytes");

    assert_eq!(ep.served_count(), 2);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn two_personas_are_header_identical() {
    // Two endpoints (as two personas' loops would be), different
    // payload bytes of equal length so the assertion cannot pass
    // vacuously by serving identical bodies.
    let a = PServeEndpoint::bind(FixtureProvider::new([(0, vec![0xAA; 2048])]))
        .await
        .expect("bind a");
    let b = PServeEndpoint::bind(FixtureProvider::new([(1, vec![0xBB; 2048])]))
        .await
        .expect("bind b");
    let ha = head_of(&fetch(a.addr(), "/x-provisional/v0/shard/0").await);
    let hb = head_of(&fetch(b.addr(), "/x-provisional/v0/shard/1").await);
    assert_eq!(ha, hb, "two personas must be header-identical");

    // The header set is exactly the declared one — checked by name so
    // a future addition fails here instead of widening the
    // fingerprint.
    assert_eq!(header_names(&ha), RESPONSE_HEADER_NAMES);
    for banned in ["server", "date", "etag", "accept-ranges", "connection"] {
        assert!(
            !ha.to_ascii_lowercase().contains(banned),
            "{banned} must not be emitted: {ha}"
        );
    }
}

#[test]
fn not_found_uses_the_declared_header_set_and_content_type() {
    // One source of truth: 404 is not a second fingerprint with a
    // divergent header list or content-type spelling.
    assert!(NOT_FOUND.contains(&format!("content-type: {CONTENT_TYPE}")));
    let head = NOT_FOUND
        .split("\r\n\r\n")
        .next()
        .expect("status + headers");
    assert_eq!(header_names(head), RESPONSE_HEADER_NAMES);
}

#[tokio::test]
async fn every_non_servable_outcome_renders_one_identical_404() {
    // The full *complete-head* miss set in one sweep: wrong path, wrong
    // prefix, malformed id, UNKNOWN shard id (a valid route to a shard
    // this persona does not hold), and a provider infrastructure
    // failure. All must be byte-identical, or the differences become a
    // probe surface for the route table, the holdings, or store health.
    // Incomplete heads (oversized / EOF / timeout) are a different
    // wire class — close, like over-capacity — covered separately.
    let ep = PServeEndpoint::bind(FixtureProvider::new([(3, leaves(1, 7))]))
        .await
        .expect("bind");
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for path in [
        "/",
        "/health",
        "/x-spike/v0/shard/3",
        "/x-provisional/v0/shard/",
        "/x-provisional/v0/shard/abc",
        "/x-provisional/v0/shard/4", // valid route, unheld shard
    ] {
        seen.push(fetch(ep.addr(), path).await);
    }
    let failing = PServeEndpoint::bind(Arc::new(FailingProvider))
        .await
        .expect("bind failing");
    seen.push(fetch(failing.addr(), "/x-provisional/v0/shard/3").await);
    assert_eq!(failing.lookup_failure_count(), 1);

    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "every miss must render byte-identically"
    );
    assert!(head_of(&seen[0]).starts_with("HTTP/1.1 404"));
    assert_eq!(ep.served_count(), 0, "a miss is not counted as a serve");
}

#[tokio::test]
async fn non_get_methods_are_not_served() {
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 1))]))
        .await
        .expect("bind");
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(b"POST /x-provisional/v0/shard/0 HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .expect("write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read");
    assert!(head_of(&out).starts_with("HTTP/1.1 404"));
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn a_request_body_does_not_reset_the_response() {
    // Unread bytes left in the receive queue at close make Linux send
    // RST instead of FIN, and the RST can destroy the response already
    // queued for sending. A complete head followed by a body must still
    // deliver the whole shared 404 — the invariant says every
    // complete-head non-servable outcome renders *the same bytes*, and
    // "reset instead" is not the same bytes.
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 1))]))
        .await
        .expect("bind");
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    let body = vec![b'z'; 64 * 1024];
    s.write_all(
        format!(
            "POST /x-provisional/v0/shard/0 HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .expect("write head");
    s.write_all(&body).await.expect("write body");

    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    assert_eq!(
        out,
        NOT_FOUND.as_bytes(),
        "the complete shared 404 must survive a request that carried a body"
    );
}

#[tokio::test]
async fn unread_request_bytes_do_not_truncate_the_served_shard() {
    // The same mechanism with real stakes. A peer that pipelines, or
    // that sends anything after a complete head, leaves bytes in the
    // receive queue; closing on top of them resets the connection and
    // the witness sees a *short shard*, failing content verification on
    // bytes this endpoint sent correctly.
    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]))
        .await
        .expect("bind");
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(b"GET /x-provisional/v0/shard/0 HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .expect("write request");
    // Never answered — no keep-alive — and exactly the unread remainder
    // that provokes the reset.
    s.write_all(&vec![b'q'; 64 * 1024])
        .await
        .expect("write trailing bytes");

    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    assert!(head_of(&out).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(
        &out[out.len() - payload.len()..],
        &payload[..],
        "the whole shard must arrive intact"
    );
    assert_eq!(ep.served_count(), 1);
}

#[tokio::test]
async fn a_slow_reader_is_not_reset_before_it_reads_the_shard() {
    // The sibling test above leaves the same unread bytes but reads
    // immediately, so a fast client empties the send buffer before the
    // server closes and the bug hides. This one pins the interleaving that
    // actually failed in CI: the client does not read until after the
    // server has written the response and finished closing.
    //
    // Pre-fix the drain stopped after MAX_DRAIN_BYTES with ~56 KiB still
    // queued, so the drop sent RST and purged the response that had not
    // been read yet — `read_to_end` returned ConnectionReset. The byte
    // bound was the whole cause: it guaranteed unread bytes remained,
    // which is precisely the condition close_gracefully exists to clear.
    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]))
        .await
        .expect("bind");
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(b"GET /x-provisional/v0/shard/0 HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .expect("write request");
    s.write_all(&vec![b'q'; 64 * 1024])
        .await
        .expect("write trailing bytes");

    // Do not read yet. The response lands in the send buffer while the
    // server drains and closes; only then does this client collect it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut out = Vec::new();
    s.read_to_end(&mut out)
        .await
        .expect("a peer with unread request bytes must still receive its response");
    assert!(head_of(&out).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(
        &out[out.len() - payload.len()..],
        &payload[..],
        "the whole shard must arrive intact for a reader that was slow to start"
    );
    assert_eq!(ep.served_count(), 1);
}

#[tokio::test]
async fn a_multi_chunk_body_arrives_whole_and_in_order() {
    // The body is streamed in WRITE_CHUNK_BYTES pieces; a chunking or
    // cursor bug shows up as reordering, duplication, or a short body,
    // none of which a same-length assertion alone would catch.
    // Three full chunks plus one leaf: still a short final chunk (the
    // cursor bug this test exists for), now a whole number of leaves.
    assert!(WRITE_CHUNK_BYTES.is_multiple_of(LEAF_BYTES));
    let payload: Vec<u8> = (0..WRITE_CHUNK_BYTES * 3 + LEAF_BYTES)
        .map(|i| u8::try_from(i % 253).expect("modulus is under 256"))
        .collect();
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]))
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
    let (head, frame, body) = parse_served(&r);
    assert!(head.contains(&format!("content-length: {}", frame.framed_len())));
    assert_eq!(
        frame.framed_len(),
        (frame.encoded_len() + payload.len()) as u64,
        "content-length covers the frame header as well as the segment"
    );
    assert_eq!(body, payload);
}

#[tokio::test]
async fn the_served_body_leads_with_the_frame_header() {
    // RF-D4 on the wire. The witness reconstructs `R_k` from the
    // segment bytes, so it needs to know where they stop; without the
    // leading lengths a padded response is indistinguishable from a
    // longer segment, and `content-length` cannot tell them apart
    // because one number covers both.
    let payload = leaves(9, 0x40);
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload.clone())]))
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;

    let (head, frame, body) = parse_served(&r);
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(frame.leaf_count(), 9);
    assert_eq!(frame.segment_bytes(), payload.len() as u64);
    assert_eq!(
        frame.padding_len(),
        0,
        "writers emit zero padding until a scheme is specified"
    );
    // The frame *delimits*: everything the header accounts for is
    // present, and nothing beyond it arrived.
    assert_eq!(body, payload);
    assert_eq!(r.len() as u64 - (head.len() + 4) as u64, frame.framed_len());
}

#[tokio::test]
async fn a_body_that_is_not_a_leaf_array_is_not_servable() {
    // The constructor-level half of the same rule, at the wire: the
    // frame declares a leaf count, so bytes that are not a leaf array
    // have no representable header. Rendering the shared 404 — rather
    // than a body some witness would then fail to verify — is what
    // keeps an unframeable payload from looking like a serve.
    struct RaggedProvider;
    impl ShardProvider for RaggedProvider {
        fn shard_bytes(&self, _shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
            // One byte short of a leaf.
            Ok(ShardBody::flat(Arc::from(
                vec![0u8; LEAF_BYTES - 1].into_boxed_slice(),
            )))
        }
    }
    let ep = PServeEndpoint::bind(Arc::new(RaggedProvider))
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
    assert_eq!(r, NOT_FOUND.as_bytes(), "an unframeable body is not served");
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn concurrency_past_the_cap_is_refused_by_close_not_by_a_status_code() {
    // Hold connections open (no request head → each keeps a permit
    // until READ_TIMEOUT). Poll until the accept loop has actually
    // filled the cap and starts shedding by CLOSE — never a fixed
    // sleep that flakes under load.
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 3))]))
        .await
        .expect("bind");

    let mut held: Vec<TcpStream> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_close_refusal = false;
    let mut refused_bodies = Vec::new();

    while tokio::time::Instant::now() < deadline {
        while held.len() < MAX_INFLIGHT {
            held.push(TcpStream::connect(ep.addr()).await.expect("connect hold"));
        }
        // Let the accept loop drain the backlog.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;

        let before = ep.refused_count();
        let mut s = TcpStream::connect(ep.addr()).await.expect("probe");
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_millis(100), s.read_to_end(&mut out))
            .await
            .ok();
        if ep.refused_count() > before {
            assert!(
                !out.starts_with(b"HTTP/"),
                "a refusal must be a close, never a status line"
            );
            saw_close_refusal = true;
            refused_bodies.push(out);
            // A few more excess arrivals for confidence.
            for _ in 0..4 {
                let mut s = TcpStream::connect(ep.addr()).await.expect("excess");
                let mut out = Vec::new();
                tokio::time::timeout(Duration::from_millis(100), s.read_to_end(&mut out))
                    .await
                    .ok();
                refused_bodies.push(out);
            }
            break;
        }
        // Still under capacity: this probe was accepted — hold it so
        // we fill the remaining slots.
        held.push(s);
    }

    assert!(
        saw_close_refusal && ep.refused_count() > 0,
        "the cap must shed load without a fixed sleep; refused = {}",
        ep.refused_count()
    );
    for body in &refused_bodies {
        assert!(
            !body.starts_with(b"HTTP/"),
            "a refusal must be a close, never a status line"
        );
    }
    drop(held);
}

#[tokio::test]
async fn the_cap_does_not_refuse_below_it() {
    // Negative control: without it, a cap of zero would pass
    // "refusals happen" while breaking the endpoint entirely.
    let payload = leaves(4, 9);
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload)]))
        .await
        .expect("bind");
    for _ in 0..8 {
        let r = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
        assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
    }
    assert_eq!(ep.refused_count(), 0, "no refusal below the cap");
    assert_eq!(ep.served_count(), 8);
}

#[tokio::test]
async fn oversized_request_head_is_closed_not_answered() {
    // Incomplete / hostile head: close with no HTTP bytes — same wire
    // class as over-capacity, not the complete-head shared 404. The
    // pre-allocation bound is enforced while reading.
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 0))]))
        .await
        .expect("bind");
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(b"GET /x-provisional/v0/shard/0 HTTP/1.1\r\n")
        .await
        .expect("write line");
    let filler = vec![b'x'; MAX_REQUEST_BYTES * 2];
    s.write_all(&filler).await.ok();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.ok();
    assert!(
        !out.starts_with(b"HTTP/"),
        "an incomplete/oversized head must close, not invent a status: {out:?}"
    );
    assert_eq!(ep.served_count(), 0);
}

#[test]
fn request_parsing_accepts_only_the_provisional_route() {
    assert_eq!(
        parse_request(b"GET /x-provisional/v0/shard/42 HTTP/1.1\r\n\r\n"),
        Some(Request::Shard(42))
    );
    assert_eq!(parse_request(b"GET /shard/42 HTTP/1.1\r\n\r\n"), None);
    // The spike's route is dead here — its framing did not carry over.
    assert_eq!(
        parse_request(b"GET /x-spike/v0/shard/42 HTTP/1.1\r\n\r\n"),
        None
    );
    assert_eq!(
        parse_request(b"HEAD /x-provisional/v0/shard/1 HTTP/1.1\r\n\r\n"),
        None
    );
    // A negative id is not a u64 — rejected rather than wrapped.
    assert_eq!(
        parse_request(b"GET /x-provisional/v0/shard/-1 HTTP/1.1\r\n\r\n"),
        None
    );
    // No version token / extra tokens → miss.
    assert_eq!(
        parse_request(b"GET /x-provisional/v0/shard/1\r\n\r\n"),
        None
    );
    assert_eq!(
        parse_request(b"GET /x-provisional/v0/shard/1 HTTP/1.1 extra\r\n\r\n"),
        None
    );
    // Query / suffix is not a bare u64.
    assert_eq!(
        parse_request(b"GET /x-provisional/v0/shard/1?x=1 HTTP/1.1\r\n\r\n"),
        None
    );
}
