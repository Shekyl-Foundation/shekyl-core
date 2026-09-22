// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Endpoint tests for [`crate::serve`]. Lives beside the production loop so
//! the file that answers the wire stays under a thousand lines; private
//! items remain visible via `#[path]` from `serve.rs`.

use super::*;
use crate::countersign::{PassKey, SignRefused, TestKeySigner};
use crate::provider::{ProviderError, ShardBody};
use shekyl_archival_retention::pass_anchor::{
    pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_LAG_BLOCKS,
    PASS_REQUEST_HEADER_LEN,
};
use shekyl_archival_retention::verify_pass_transcript;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::{ServedFrameHeader, LEAF_BYTES};
use shekyl_types::BlockHeight;

/// The test persona's own height, and the anchor a requester at the same
/// tip would attach (`tip − 720`), which sits at the centre of the gate.
const OWN_HEIGHT: u64 = 10_000;
const IN_GATE_ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
const NONCE: [u8; 32] = [0x5a; 32];
const ANCHOR_HASH: [u8; 32] = [0xa5; 32];

fn header_at(anchor_height: u64) -> [u8; PASS_REQUEST_HEADER_LEN] {
    pass_request_header_bytes(&NONCE, BlockHeight::from_raw(anchor_height), &ANCHOR_HASH)
}

fn good_header() -> [u8; PASS_REQUEST_HEADER_LEN] {
    header_at(IN_GATE_ANCHOR)
}

fn header_line(bytes: &[u8; PASS_REQUEST_HEADER_LEN]) -> String {
    format!(
        "{REQUEST_HEADER_NAME}: {}\r\n",
        encode_request_header(bytes)
    )
}

/// Bind with a fresh ephemeral test signer at [`OWN_HEIGHT`]; the signer is
/// returned so a test can verify the countersignature or move the height.
async fn bind(provider: Arc<dyn ShardProvider>) -> (PServeEndpoint, Arc<TestKeySigner>) {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let ep = PServeEndpoint::bind(provider, Arc::clone(&signer) as Arc<dyn PassSigner>)
        .await
        .expect("bind");
    (ep, signer)
}

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

/// A 200 response, split at its seams.
struct Served {
    head: String,
    signature: HybridSignature,
    frame: ServedFrameHeader,
    body: Vec<u8>,
}

/// Split a 200 response into head, countersignature envelope, frame
/// header, payload.
fn parse_served(response: &[u8]) -> Served {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    let head = String::from_utf8_lossy(&response[..end]).to_string();
    let after_head = &response[end + 4..];
    let (sig, mut body) = after_head.split_at(SIGNATURE_ENVELOPE_LEN);
    let signature =
        HybridSignature::from_canonical_bytes(sig).expect("served body leads with a signature");
    let frame = ServedFrameHeader::read(&mut body).expect("served body carries a frame header");
    Served {
        head,
        signature,
        frame,
        body: body.to_vec(),
    }
}

/// Provider whose every lookup fails — the store-failure arm.
struct FailingProvider;

impl ShardProvider for FailingProvider {
    fn shard_bytes(&self, _shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        Err(ProviderError::other("synthetic store failure"))
    }
}

/// `GET path` with a well-formed, in-gate request header.
async fn fetch(addr: SocketAddr, path: &str) -> Vec<u8> {
    request(addr, "GET", path).await
}

/// One complete request head carrying the good header; returns the
/// response bytes.
async fn request(addr: SocketAddr, method: &str, path: &str) -> Vec<u8> {
    request_raw(
        addr,
        &format!(
            "{method} {path} HTTP/1.1\r\nhost: x\r\n{}\r\n",
            header_line(&good_header())
        ),
    )
    .await
}

/// An arbitrary complete head, verbatim; returns the response bytes.
async fn request_raw(addr: SocketAddr, head: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(head.as_bytes()).await.expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    out
}

/// The good request head for `GET /shard/0`, as bytes a test can extend.
fn good_get_shard_0() -> String {
    format!(
        "GET /shard/0 HTTP/1.1\r\nhost: x\r\n{}\r\n",
        header_line(&good_header())
    )
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
    let (ep, _) = bind(FixtureProvider::new([])).await;
    assert!(ep.addr().ip().is_loopback());
    assert_ne!(ep.addr().port(), 0, "an ephemeral port was actually bound");
}

#[tokio::test]
async fn serves_each_shard_by_its_own_id() {
    // The capability the spike lacked: the id in the route selects the
    // shard. Two ids must return their own bytes, not a shared buffer.
    let a: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let b: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
    let (ep, _) = bind(FixtureProvider::new([(7, a.clone()), (9, b.clone())])).await;

    let ra = fetch(ep.addr(), "/shard/7").await;
    assert!(head_of(&ra).starts_with("HTTP/1.1 200 OK"));
    assert_eq!(&ra[ra.len() - a.len()..], &a[..], "shard 7 serves a-bytes");

    let rb = fetch(ep.addr(), "/shard/9").await;
    assert_eq!(&rb[rb.len() - b.len()..], &b[..], "shard 9 serves b-bytes");

    assert_eq!(ep.served_count(), 2);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn two_personas_are_header_identical() {
    // Two endpoints (as two personas' loops would be), different
    // payload bytes of equal length so the assertion cannot pass
    // vacuously by serving identical bodies.
    let (a, _) = bind(FixtureProvider::new([(0, vec![0xAA; 2048])])).await;
    let (b, _) = bind(FixtureProvider::new([(1, vec![0xBB; 2048])])).await;
    let ha = head_of(&fetch(a.addr(), "/shard/0").await);
    let hb = head_of(&fetch(b.addr(), "/shard/1").await);
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
    let not_found = render_not_found();
    assert!(not_found.contains(&format!("content-type: {CONTENT_TYPE}")));
    let head = not_found
        .split("\r\n\r\n")
        .next()
        .expect("status + headers");
    assert_eq!(header_names(head), RESPONSE_HEADER_NAMES);
}

#[tokio::test]
async fn every_non_servable_outcome_renders_one_identical_404() {
    // Every complete-head miss is the one `render_not_found()`. A 405, a 500, or a
    // second 404 shape is an implementation fingerprint; a distinct
    // store-failure response is a live health oracle. Holdings are
    // chain-public — GET 200 vs 404 is already the availability oracle —
    // so this is not an existence test. It does NOT cover incomplete heads
    // (oversized / EOF / timeout): those close, like over-capacity.
    let (ep, _) = bind(FixtureProvider::new([(3, leaves(1, 7))])).await;
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for (method, path) in [
        ("GET", "/"),
        ("GET", "/health"),
        ("GET", "/x-spike/v0/shard/3"),
        ("GET", "/x-provisional/v0/shard/3"), // RF-R1 predecessor — a miss, not an alias
        ("GET", "/shard/"),
        ("GET", "/shard/abc"),
        ("GET", "/shard/4"), // valid route, unheld shard
        // Wrong METHOD on a path GET would serve: a method-aware server
        // answers 405 or 200 here. Either is a second shape, not an
        // existence leak.
        ("POST", "/shard/3"),
        ("HEAD", "/shard/3"),
        ("PUT", "/shard/3"),
        ("DELETE", "/shard/3"),
        ("OPTIONS", "/shard/3"),
    ] {
        seen.push(request(ep.addr(), method, path).await);
    }

    // The request header's failure modes (`SF-D5`): each is the same 404
    // as a wrong path. Names are case-insensitive and OWS is trimmed (that
    // is HTTP, not a second encoding); the value is canonical or nothing.
    let good = encode_request_header(&good_header());
    let mut uppercase = good.clone();
    uppercase.make_ascii_uppercase();
    for head in [
        // Missing entirely.
        "GET /shard/3 HTTP/1.1\r\nhost: x\r\n\r\n".to_string(),
        // Duplicate — even when both copies are valid.
        format!(
            "GET /shard/3 HTTP/1.1\r\n{}{}\r\n",
            header_line(&good_header()),
            header_line(&good_header())
        ),
        // Non-canonical hex (uppercase).
        format!("GET /shard/3 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {uppercase}\r\n\r\n"),
        // Wrong length: one byte short, one byte long, empty.
        format!(
            "GET /shard/3 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {}\r\n\r\n",
            &good[..good.len() - 2]
        ),
        format!("GET /shard/3 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {good}00\r\n\r\n"),
        format!("GET /shard/3 HTTP/1.1\r\n{REQUEST_HEADER_NAME}:\r\n\r\n"),
        // Not hex at all.
        format!(
            "GET /shard/3 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {}\r\n\r\n",
            "zz".repeat(PASS_REQUEST_HEADER_LEN)
        ),
        // Out of gate, both sides.
        format!(
            "GET /shard/3 HTTP/1.1\r\n{}\r\n",
            header_line(&header_at(
                IN_GATE_ANCHOR - PASS_ANCHOR_LAG_BLOCKS.to_raw() - 1
            ))
        ),
        format!(
            "GET /shard/3 HTTP/1.1\r\n{}\r\n",
            header_line(&header_at(
                IN_GATE_ANCHOR + PASS_ANCHOR_LAG_BLOCKS.to_raw() + 1
            ))
        ),
    ] {
        seen.push(request_raw(ep.addr(), &head).await);
    }
    assert_eq!(
        ep.lookup_failure_count(),
        0,
        "header refusals happen before the store is touched"
    );

    let (failing, _) = bind(Arc::new(FailingProvider)).await;
    seen.push(fetch(failing.addr(), "/shard/3").await);
    assert_eq!(failing.lookup_failure_count(), 1);

    for resp in &seen {
        assert_eq!(
            resp.as_slice(),
            render_not_found().as_bytes(),
            "every complete-head miss must be the shared 404"
        );
    }
    assert_eq!(ep.served_count(), 0, "a miss is not counted as a serve");
}

#[tokio::test]
async fn a_request_body_does_not_reset_the_response() {
    // Unread bytes left in the receive queue at close make Linux send
    // RST instead of FIN, and the RST can destroy the response already
    // queued for sending. A complete head followed by a body must still
    // deliver the whole shared 404 — the invariant says every
    // complete-head non-servable outcome renders *the same bytes*, and
    // "reset instead" is not the same bytes.
    let (ep, _) = bind(FixtureProvider::new([(0, leaves(1, 1))])).await;
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    let body = vec![b'z'; 64 * 1024];
    s.write_all(
        format!(
            "POST /shard/0 HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\n\r\n",
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
        render_not_found().as_bytes(),
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
    let (ep, _) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(good_get_shard_0().as_bytes())
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
    let (ep, _) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(good_get_shard_0().as_bytes())
        .await
        .expect("write request");
    s.write_all(&vec![b'q'; 64 * 1024])
        .await
        .expect("write trailing bytes");
    // Half-close so the drain observes EOF and the server's close completes
    // promptly. Without this the server sits in close_gracefully until
    // DRAIN_TIMEOUT, and the read below would race that 2s window rather
    // than testing what happens after the close — the unread bytes that
    // provoke the reset are already queued either way.
    s.shutdown()
        .await
        .expect("half-close the client write side");

    // Do not read yet. The response sits in the send buffer while the server
    // drains and closes; only then does this client collect it.
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
    let (ep, _) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let r = fetch(ep.addr(), "/shard/0").await;
    let Served {
        head, frame, body, ..
    } = parse_served(&r);
    let expected_len = SIGNATURE_ENVELOPE_LEN as u64 + frame.framed_len();
    assert!(head.contains(&format!("content-length: {expected_len}")));
    assert_eq!(
        frame.framed_len(),
        (frame.encoded_len() + payload.len()) as u64,
        "the frame covers its header as well as the segment"
    );
    assert_eq!(body, payload);
}

#[tokio::test]
async fn the_served_body_leads_with_the_countersignature_then_the_frame() {
    // SF-D8 then RF-D4 on the wire. The signature binds the response to
    // the request the witness made (nonce, anchor, shard id); the frame
    // tells it where the segment bytes stop, so a padded response is not
    // mistaken for a longer segment. One `content-length` covers both.
    let payload = leaves(9, 0x40);
    let (ep, signer) = bind(FixtureProvider::new([(0, payload.clone())])).await;
    let r = fetch(ep.addr(), "/shard/0").await;

    let Served {
        head,
        signature,
        frame,
        body,
    } = parse_served(&r);
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    // The countersignature verifies through the consensus verifier the
    // daemon runs, against exactly the header the request carried.
    verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &signature,
    )
    .expect("the served signature covers the request header and shard id");
    // ...and is bound to *this* shard id and *this* nonce.
    assert!(verify_pass_transcript(
        signer.public_key(),
        &NONCE,
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        1,
        &signature
    )
    .is_err());
    assert!(verify_pass_transcript(
        signer.public_key(),
        &[0u8; 32],
        BlockHeight::from_raw(IN_GATE_ANCHOR),
        &ANCHOR_HASH,
        0,
        &signature
    )
    .is_err());

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
    assert_eq!(
        r.len() as u64 - (head.len() + 4) as u64,
        SIGNATURE_ENVELOPE_LEN as u64 + frame.framed_len()
    );
}

#[tokio::test]
async fn the_gate_is_two_sided_with_the_admission_lag() {
    // `anchor_height ∈ [p − 720 − L, p − 720 + L]`: both edges serve, one
    // past either edge is the shared 404 with no store read and no sign.
    let (ep, _) = bind(FixtureProvider::new([(0, leaves(1, 1))])).await;
    let l = PASS_ANCHOR_LAG_BLOCKS.to_raw();
    for (anchor, servable) in [
        (IN_GATE_ANCHOR, true),
        (IN_GATE_ANCHOR - l, true),
        (IN_GATE_ANCHOR + l, true),
        (IN_GATE_ANCHOR - l - 1, false),
        (IN_GATE_ANCHOR + l + 1, false),
        (OWN_HEIGHT, false), // a requester anchoring at *its tip* is refused
    ] {
        let r = request_raw(
            ep.addr(),
            &format!(
                "GET /shard/0 HTTP/1.1\r\n{}\r\n",
                header_line(&header_at(anchor))
            ),
        )
        .await;
        if servable {
            assert!(
                head_of(&r).starts_with("HTTP/1.1 200 OK"),
                "anchor {anchor}"
            );
        } else {
            assert_eq!(r, render_not_found().as_bytes(), "anchor {anchor}");
        }
    }
    assert_eq!(ep.served_count(), 3);
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.sign_failure_count(), 0);
}

#[tokio::test]
async fn a_refusing_signer_renders_the_shared_404_and_counts_separately() {
    // The host's key is not resident (SH-2 not yet wired, signer down):
    // the endpoint stays up, the shard is looked up, and the response is
    // the identical 404 — never an unsigned body. The counter is the only
    // place this is distinguishable from a missing pin.
    struct Refusing;
    impl PassKey for Refusing {
        fn sign_pass(
            &self,
            _: &[u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
        ) -> Result<HybridSignature, SignRefused> {
            Err(SignRefused::new("not resident"))
        }
    }
    impl PassSigner for Refusing {
        fn own_height(&self) -> Option<BlockHeight> {
            Some(BlockHeight::from_raw(OWN_HEIGHT))
        }
    }
    let signer: Arc<dyn PassSigner> = Arc::new(Refusing);
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 1))]), signer)
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
    // An unheld shard is an ordinary miss — neither a lookup failure nor
    // a sign failure: the persona never signs for a shard it does not
    // hold, and not holding one is not a fault.
    let r = fetch(ep.addr(), "/shard/9").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.sign_failure_count(), 1);
    assert_eq!(ep.lookup_failure_count(), 0);
}

#[tokio::test]
async fn an_unreadable_height_renders_the_shared_404_and_counts_a_lookup_failure() {
    // The host cannot read its own height — its serving store is gone.
    // Nothing is looked up and nothing is signed: the 404 is identical,
    // and the fault lands in `lookup_failure_count` (a store read that
    // failed), not in `sign_failure_count` and not silently in neither.
    struct Storeless(Arc<TestKeySigner>);
    impl PassKey for Storeless {
        fn sign_pass(
            &self,
            m: &[u8; shekyl_archival_retention::pass_anchor::PASS_COUNTERSIGNATURE_MESSAGE_LEN],
        ) -> Result<HybridSignature, SignRefused> {
            self.0.sign_pass(m)
        }
    }
    impl PassSigner for Storeless {
        fn own_height(&self) -> Option<BlockHeight> {
            None
        }
    }
    let key = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let signer: Arc<dyn PassSigner> = Arc::new(Storeless(Arc::clone(&key)));
    let ep = PServeEndpoint::bind(FixtureProvider::new([(0, leaves(1, 1))]), signer)
        .await
        .expect("bind");
    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(r, render_not_found().as_bytes());
    assert_eq!(ep.lookup_failure_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0);
    assert_eq!(ep.served_count(), 0);
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
    let (ep, _) = bind(Arc::new(RaggedProvider)).await;
    let r = fetch(ep.addr(), "/shard/0").await;
    assert_eq!(
        r,
        render_not_found().as_bytes(),
        "an unframeable body is not served"
    );
    assert_eq!(ep.served_count(), 0);
}

#[tokio::test]
async fn concurrency_past_the_cap_is_refused_by_close_not_by_a_status_code() {
    // Hold connections open (no request head → each keeps a permit
    // until READ_TIMEOUT). Poll until the accept loop has actually
    // filled the cap and starts shedding by CLOSE — never a fixed
    // sleep that flakes under load.
    let (ep, _) = bind(FixtureProvider::new([(0, leaves(1, 3))])).await;

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
    let (ep, _) = bind(FixtureProvider::new([(0, payload)])).await;
    for _ in 0..8 {
        let r = fetch(ep.addr(), "/shard/0").await;
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
    let (ep, _) = bind(FixtureProvider::new([(0, leaves(1, 0))])).await;
    let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
    s.write_all(b"GET /shard/0 HTTP/1.1\r\n")
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
fn route_prefix_is_the_rf_r1_path() {
    assert_eq!(ROUTE_PREFIX, "/shard/");
    assert!(!ROUTE_PREFIX.contains("provisional"));
    assert!(!ROUTE_PREFIX.contains("v0"));
}

#[test]
fn request_parsing_accepts_only_the_ruled_route() {
    let h = header_line(&good_header());
    let with_header = |line: &str| format!("{line}\r\n{h}\r\n");
    assert_eq!(
        parse_request(with_header("GET /shard/42 HTTP/1.1").as_bytes()),
        Some(Request::Shard {
            shard_id: 42,
            header: good_header()
        })
    );
    // Discarded RF-R1 predecessor — a miss, not an alias.
    assert_eq!(
        parse_request(with_header("GET /x-provisional/v0/shard/42 HTTP/1.1").as_bytes()),
        None
    );
    // The spike's route is dead here — its framing did not carry over.
    assert_eq!(
        parse_request(with_header("GET /x-spike/v0/shard/42 HTTP/1.1").as_bytes()),
        None
    );
    assert_eq!(
        parse_request(with_header("HEAD /shard/1 HTTP/1.1").as_bytes()),
        None
    );
    // A negative id is not a u64 — rejected rather than wrapped.
    assert_eq!(
        parse_request(with_header("GET /shard/-1 HTTP/1.1").as_bytes()),
        None
    );
    // No version token / extra tokens → miss.
    assert_eq!(parse_request(with_header("GET /shard/1").as_bytes()), None);
    assert_eq!(
        parse_request(with_header("GET /shard/1 HTTP/1.1 extra").as_bytes()),
        None
    );
    // Query / suffix is not a bare u64.
    assert_eq!(
        parse_request(with_header("GET /shard/1?x=1 HTTP/1.1").as_bytes()),
        None
    );
}

#[test]
fn request_header_parsing_is_http_lenient_and_value_strict() {
    let good = encode_request_header(&good_header());
    let expect = Some(Request::Shard {
        shard_id: 1,
        header: good_header(),
    });
    // Name case and optional whitespace are HTTP's; other headers are
    // ignored on either side.
    let upper_name = REQUEST_HEADER_NAME.to_ascii_uppercase();
    assert_eq!(
        parse_request(
            format!("GET /shard/1 HTTP/1.1\r\nhost: x\r\n{upper_name}:\t {good} \r\nx: y\r\n\r\n")
                .as_bytes()
        ),
        expect
    );
    // Missing → miss.
    assert_eq!(
        parse_request(b"GET /shard/1 HTTP/1.1\r\nhost: x\r\n\r\n"),
        None
    );
    // Duplicate → miss, even if identical.
    assert_eq!(
        parse_request(
            format!("GET /shard/1 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {good}\r\n{REQUEST_HEADER_NAME}: {good}\r\n\r\n")
                .as_bytes()
        ),
        None
    );
    // The value is canonical lowercase hex of exactly 72 bytes.
    let mut upper_value = good.clone();
    upper_value.make_ascii_uppercase();
    assert_eq!(
        parse_request(
            format!("GET /shard/1 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {upper_value}\r\n\r\n")
                .as_bytes()
        ),
        None
    );
    assert_eq!(
        parse_request(
            format!("GET /shard/1 HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {good}0\r\n\r\n").as_bytes()
        ),
        None
    );
    // A header line with no colon is a malformed head → miss.
    assert_eq!(
        parse_request(
            format!(
                "GET /shard/1 HTTP/1.1\r\nno-colon-here\r\n{REQUEST_HEADER_NAME}: {good}\r\n\r\n"
            )
            .as_bytes()
        ),
        None
    );
    // The header is only read from the head: a copy after the blank line
    // (pipelined bytes) does not count.
    assert_eq!(
        parse_request(
            format!("GET /shard/1 HTTP/1.1\r\n\r\n{REQUEST_HEADER_NAME}: {good}\r\n\r\n")
                .as_bytes()
        ),
        None
    );
}
