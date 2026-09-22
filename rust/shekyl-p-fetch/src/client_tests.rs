// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client against an in-crate stub that is both the SOCKS5 proxy and
//! `P`: it accepts the SOCKS handshake, records what the client asked the
//! proxy to resolve, reads the HTTP request, and then plays one scripted
//! response. Every `SF-D6` outcome is driven from here.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ServingEndpoint;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::{
    max_body_bytes, ContentRefused, ContentVerify, FetchError, FetchTarget, Malformed,
    PFetchClient, RequestHeader, Stall, Timeouts, VerifiedShard, MAX_INFLIGHT,
    SIGNATURE_ENVELOPE_LEN,
};

const SHARD: u64 = 17;
const CONTENT: &[u8] = b"frame bytes the hole will look at";

/// What the stub saw before it answered.
#[derive(Debug)]
struct Seen {
    /// SOCKS5 ATYP byte of the CONNECT.
    atyp: u8,
    /// The destination the client asked the proxy to resolve.
    domain: String,
    port: u16,
    /// The HTTP request head, verbatim.
    request: String,
}

#[derive(Clone)]
enum Script {
    /// Reply with these bytes, then close.
    Respond(Vec<u8>),
    /// Reply with the first bytes, pause long enough for the client to be
    /// probing for the close, then send the second and close — a trailer
    /// that cannot have been buffered behind the head.
    RespondThenTrail(Vec<u8>, Vec<u8>),
    /// Reply with these bytes and hold the connection open — a `P` that
    /// finished the body and never closed.
    RespondHoldOpen(Vec<u8>),
    /// Complete the handshake, read the request, then say nothing until
    /// the client gives up.
    Silent,
    /// Complete the handshake, read the request, then close with no HTTP
    /// bytes — `P`'s over-capacity shape.
    CloseBeforeHead,
    /// Refuse the SOCKS CONNECT.
    RefuseConnect,
    /// Never terminate the head.
    EndlessHead,
}

struct Stub {
    proxy: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    _task: JoinHandle<()>,
}

impl Stub {
    async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let record = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let script = script.clone();
                let record = Arc::clone(&record);
                tokio::spawn(serve_one(stream, script, record));
            }
        });
        Self {
            proxy,
            seen,
            _task: task,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

/// SOCKS5 no-auth greeting, CONNECT with the destination recorded, then
/// the script. What was seen is recorded **before** the script plays, so
/// a scripted silence still leaves its exchange on the record.
async fn serve_one(mut s: TcpStream, script: Script, record: Arc<Mutex<Vec<Seen>>>) -> Option<()> {
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await.ok()?;
    assert_eq!(greeting[0], 5, "SOCKS version");
    let mut methods = vec![0u8; usize::from(greeting[1])];
    s.read_exact(&mut methods).await.ok()?;
    assert!(methods.contains(&0), "no-auth must be offered");
    s.write_all(&[5, 0]).await.ok()?;

    let mut request = [0u8; 4];
    s.read_exact(&mut request).await.ok()?;
    assert_eq!(request[1], 1, "CONNECT");
    let atyp = request[3];
    let domain = match atyp {
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            s.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).expect("domain is text")
        }
        1 | 4 => {
            let mut addr = vec![0u8; if atyp == 1 { 4 } else { 16 }];
            s.read_exact(&mut addr).await.ok()?;
            format!("{addr:?}")
        }
        other => panic!("unknown ATYP {other:#04x}"),
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await.ok()?;
    let port = u16::from_be_bytes(port);

    if matches!(script, Script::RefuseConnect) {
        // General SOCKS server failure.
        s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
        record.lock().unwrap().push(Seen {
            atyp,
            domain,
            port,
            request: String::new(),
        });
        return Some(());
    }
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;

    let mut head = Vec::new();
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.ok()?;
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    record.lock().unwrap().push(Seen {
        atyp,
        domain,
        port,
        request: String::from_utf8(head).expect("request is text"),
    });

    match script {
        Script::Respond(bytes) => {
            s.write_all(&bytes).await.ok()?;
            s.shutdown().await.ok()?;
        }
        Script::RespondThenTrail(bytes, trailer) => {
            s.write_all(&bytes).await.ok()?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            s.write_all(&trailer).await.ok()?;
            s.shutdown().await.ok()?;
        }
        Script::RespondHoldOpen(bytes) => {
            s.write_all(&bytes).await.ok()?;
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        Script::Silent => {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        Script::CloseBeforeHead | Script::RefuseConnect => {}
        Script::EndlessHead => {
            s.write_all(b"HTTP/1.1 200 OK\r\n").await.ok()?;
            loop {
                s.write_all(b"x-pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
                    .await
                    .ok()?;
            }
        }
    }
    Some(())
}

/// A hole that records what it was shown and answers as configured.
struct Hole {
    refuse: Option<&'static str>,
    shown: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl Hole {
    fn accepting() -> Arc<Self> {
        Arc::new(Self {
            refuse: None,
            shown: Mutex::default(),
        })
    }
    fn refusing(reason: &'static str) -> Arc<Self> {
        Arc::new(Self {
            refuse: Some(reason),
            shown: Mutex::default(),
        })
    }
    fn shown(&self) -> Vec<(u64, Vec<u8>)> {
        self.shown.lock().unwrap().clone()
    }
}

impl ContentVerify for Hole {
    fn verify(&self, shard_id: u64, body: &[u8]) -> Result<(), ContentRefused> {
        self.shown.lock().unwrap().push((shard_id, body.to_vec()));
        match self.refuse {
            Some(reason) => Err(ContentRefused::new(reason)),
            None => Ok(()),
        }
    }
}

struct Keys {
    public: HybridPublicKey,
    secret: HybridSecretKey,
}

fn keys() -> Keys {
    let (public, secret) = HybridEd25519MlDsa
        .generate_ephemeral_keypair_for_tests()
        .expect("keygen");
    Keys { public, secret }
}

fn sign(keys: &Keys, header: &RequestHeader, shard_id: u64) -> HybridSignature {
    HybridEd25519MlDsa
        .sign(
            &keys.secret,
            SCHEME_DOMAIN_ATTESTATION,
            &header.transcript(shard_id),
        )
        .expect("sign")
}

fn endpoint() -> ServingEndpoint {
    ServingEndpoint::from_record_bytes([0x42; 32])
}

fn target(keys: &Keys) -> FetchTarget {
    FetchTarget {
        endpoint: endpoint(),
        verifying_key: keys.public.clone(),
        shard_id: SHARD,
    }
}

fn header() -> RequestHeader {
    RequestHeader::with_nonce([0xa5; 32], BlockHeight::from_raw(9_000), [0x5a; 32])
}

fn fast() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(300),
        body_stall: Duration::from_millis(300),
        body_total: Duration::from_millis(1_500),
    }
}

fn ok_response(envelope: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n",
        shekyl_curve_tree::serving_route::CONTENT_TYPE,
        envelope.len() + content.len()
    )
    .into_bytes();
    out.extend_from_slice(envelope);
    out.extend_from_slice(content);
    out
}

fn head_only(status_line: &str, headers: &str) -> Vec<u8> {
    format!("{status_line}\r\n{headers}\r\n\r\n").into_bytes()
}

fn signed_response(keys: &Keys, header: &RequestHeader, shard_id: u64) -> Vec<u8> {
    let sig = sign(keys, header, shard_id).to_canonical_bytes().unwrap();
    assert_eq!(sig.len(), SIGNATURE_ENVELOPE_LEN);
    ok_response(&sig, CONTENT)
}

async fn run(
    script: Script,
    hole: Arc<Hole>,
    keys: &Keys,
) -> (Result<VerifiedShard, FetchError>, Vec<Seen>) {
    let stub = Stub::start(script).await;
    let client = PFetchClient::with_timeouts(stub.proxy, fast());
    let out = client.fetch(&target(keys), &header(), hole).await;
    // Let the stub finish recording.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (out, stub.seen())
}

fn stall(r: Result<VerifiedShard, FetchError>) -> Stall {
    match r {
        Err(FetchError::Stall(s)) => s,
        Err(other) => panic!("not a stall: {other}"),
        Ok(_) => panic!("fetched"),
    }
}

fn malformed(r: Result<VerifiedShard, FetchError>) -> Malformed {
    match r {
        Err(FetchError::Malformed(m)) => m,
        Err(other) => panic!("not malformed: {other}"),
        Ok(_) => panic!("fetched"),
    }
}

// ---------------------------------------------------------------- happy path

#[tokio::test]
async fn a_signed_shard_comes_back_verified_and_the_proxy_got_the_onion_name() {
    let keys = keys();
    let hole = Hole::accepting();
    let (out, seen) = run(
        Script::Respond(signed_response(&keys, &header(), SHARD)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    let shard = out.expect("fetched");
    assert_eq!(shard.shard_id(), SHARD);
    assert_eq!(shard.body(), CONTENT);
    assert_eq!(
        shard.signature().to_canonical_bytes().unwrap().len(),
        SIGNATURE_ENVELOPE_LEN
    );
    // The hole saw exactly the bytes after the envelope, for this shard.
    assert_eq!(hole.shown(), vec![(SHARD, CONTENT.to_vec())]);

    // SF-D3: ATYP=DOMAIN, the `.onion` name, port 80; nothing resolved here.
    let [s] = seen.as_slice() else {
        panic!("one exchange, saw {seen:?}")
    };
    assert_eq!(s.atyp, 3, "ATYP must be DOMAIN, got {:#04x}", s.atyp);
    assert_eq!(s.domain, endpoint().onion_address());
    assert_eq!(s.port, 80);
    // SF-D5: the route and the one header, nothing else.
    assert_eq!(
        s.request,
        format!(
            "GET /shard/{SHARD} HTTP/1.1\r\nshekyl-pass-request: {}\r\n\r\n",
            header().wire_value()
        )
    );
}

#[tokio::test]
async fn into_body_hands_over_the_content_without_the_envelope() {
    let keys = keys();
    let (out, _) = run(
        Script::Respond(signed_response(&keys, &header(), SHARD)),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(out.expect("fetched").into_body(), CONTENT);
}

// ------------------------------------------------------------------ SF-D6: miss

#[tokio::test]
async fn a_404_is_a_miss_and_is_not_retried_on_the_same_p() {
    let keys = keys();
    let hole = Hole::accepting();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 404 Not Found",
            "content-type: application/octet-stream\r\ncontent-length: 0",
        )),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    let err = out.expect_err("miss");
    assert!(matches!(err, FetchError::Miss), "{err}");
    assert!(!err.retries_same_p());
    assert!(
        hole.shown().is_empty(),
        "the hole is not consulted on a miss"
    );
}

#[tokio::test]
async fn a_404_with_a_body_is_not_the_contract() {
    let keys = keys();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 404 Not Found",
            "content-type: application/octet-stream\r\ncontent-length: 3",
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentLength);
}

#[tokio::test]
async fn a_404_declaring_nothing_but_sending_bytes_is_not_the_identical_404() {
    // `content-length: 0` is honoured to the byte. A "no" with payload
    // behind it is a `P` off the contract, not a miss to record.
    let keys = keys();
    let mut bytes = head_only(
        "HTTP/1.1 404 Not Found",
        "content-type: application/octet-stream\r\ncontent-length: 0",
    );
    bytes.extend_from_slice(b"but here is something anyway");
    let (out, _) = run(Script::Respond(bytes), Hole::accepting(), &keys).await;
    assert_eq!(malformed(out), Malformed::Overlength { declared: 0 });
}

// ------------------------------------------------------- overlength and close

#[tokio::test]
async fn bytes_past_content_length_are_malformed_not_trimmed() {
    // A valid signed body with a trailer. Trimming the trailer would let
    // `P` ship anything behind a verifying prefix; SF-D6 says body long
    // of agreed `N` is malformed, so the fetch is refused whether the
    // trailer arrived with the head or on the probe for the close.
    let keys = keys();
    let hole = Hole::accepting();
    let mut bytes = signed_response(&keys, &header(), SHARD);
    bytes.extend_from_slice(b"trailer");
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN + CONTENT.len()).unwrap();
    let (out, _) = run(Script::Respond(bytes), Arc::clone(&hole), &keys).await;
    assert_eq!(malformed(out), Malformed::Overlength { declared });
    assert!(
        hole.shown().is_empty(),
        "nothing is verified from a response that is not the contract"
    );
}

#[tokio::test]
async fn a_late_trailer_is_caught_on_the_probe_for_the_close() {
    // The body is complete and verifiable; the excess arrives only after
    // the client has it all. The probe that a conforming `P` answers
    // with EOF is answered with a byte instead.
    let keys = keys();
    let hole = Hole::accepting();
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN + CONTENT.len()).unwrap();
    let (out, _) = run(
        Script::RespondThenTrail(signed_response(&keys, &header(), SHARD), b"x".to_vec()),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Overlength { declared });
    assert!(hole.shown().is_empty());
}

#[tokio::test]
async fn a_complete_body_with_no_close_is_a_stall() {
    // Every byte arrived; `P` just never hung up. The client cannot call
    // the body final until it sees EOF, and a `P` that goes quiet instead
    // is wedged — a stall, retried like one — not lying.
    let keys = keys();
    let (out, _) = run(
        Script::RespondHoldOpen(signed_response(&keys, &header(), SHARD)),
        Hole::accepting(),
        &keys,
    )
    .await;
    let err = out.expect_err("not final");
    assert!(err.retries_same_p());
    assert!(matches!(err, FetchError::Stall(Stall::NoClose)), "{err}");
}

// ------------------------------------------------------------- SF-D6: malformed

#[tokio::test]
async fn any_other_complete_head_is_malformed_and_typed() {
    let keys = keys();
    let two = "content-type: application/octet-stream\r\ncontent-length: 0";

    let (out, _) = run(
        Script::Respond(head_only("HTTP/1.1 500 Oops", two)),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Status(500));

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!("{two}\r\nserver: nginx"),
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::HeaderSet);

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            "content-type: text/html\r\ncontent-length: 0",
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentType);

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            "content-type: application/octet-stream\r\ncontent-length: x",
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentLength);

    let (out, _) = run(Script::EndlessHead, Hole::accepting(), &keys).await;
    assert_eq!(malformed(out), Malformed::HeadTooLong);
}

#[tokio::test]
async fn the_body_is_bounded_from_the_head_before_a_byte_is_read() {
    let keys = keys();
    let max = max_body_bytes();

    // Too short to hold a signature.
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN).unwrap() - 1;
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!("content-type: application/octet-stream\r\ncontent-length: {declared}"),
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::EnvelopeShort { declared });

    // Exactly the ceiling is admitted (and then truncates, since the stub
    // sends no body); one past it is refused from the head.
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!(
                "content-type: application/octet-stream\r\ncontent-length: {}",
                max + 1
            ),
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert_eq!(
        malformed(out),
        Malformed::Oversize {
            declared: max + 1,
            max
        }
    );
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!("content-type: application/octet-stream\r\ncontent-length: {max}"),
        )),
        Hole::accepting(),
        &keys,
    )
    .await;
    assert!(matches!(stall(out), Stall::Truncated { declared, received: 0 } if declared == max));
}

#[tokio::test]
async fn an_envelope_that_is_not_a_canonical_signature_is_malformed() {
    let keys = keys();
    let hole = Hole::accepting();
    let (out, _) = run(
        Script::Respond(ok_response(&[0xffu8; SIGNATURE_ENVELOPE_LEN], CONTENT)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Envelope);
    assert!(hole.shown().is_empty());
}

// ----------------------------------------------------------------- SF-D6: stall

#[tokio::test]
async fn every_incomplete_exchange_is_a_stall_that_retries_the_same_p() {
    let keys = keys();

    let (out, _) = run(Script::Silent, Hole::accepting(), &keys).await;
    let err = out.expect_err("stall");
    assert!(err.retries_same_p());
    assert!(
        matches!(err, FetchError::Stall(Stall::HeadTimeout)),
        "{err}"
    );

    let (out, _) = run(Script::CloseBeforeHead, Hole::accepting(), &keys).await;
    assert!(matches!(stall(out), Stall::ClosedBeforeHead));

    let (out, seen) = run(Script::RefuseConnect, Hole::accepting(), &keys).await;
    assert!(matches!(stall(out), Stall::Dial(_)));
    assert_eq!(seen.len(), 1, "the CONNECT reached the proxy");

    // Truncation: the head promises more than the stream carries.
    let sig = sign(&keys, &header(), SHARD).to_canonical_bytes().unwrap();
    let mut short = ok_response(&sig, CONTENT);
    short.truncate(short.len() - 5);
    let (out, _) = run(Script::Respond(short), Hole::accepting(), &keys).await;
    let declared = u64::try_from(sig.len() + CONTENT.len()).unwrap();
    assert!(matches!(
        stall(out),
        Stall::Truncated { declared: d, received } if d == declared && received == declared - 5
    ));
}

#[tokio::test]
async fn a_proxy_that_is_not_listening_is_a_dial_stall() {
    let keys = keys();
    // Bind and drop: the port is now closed.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let client = PFetchClient::with_timeouts(closed, fast());
    let out = client
        .fetch(&target(&keys), &header(), Hole::accepting())
        .await;
    assert!(matches!(stall(out), Stall::Dial(_)));
}

// ------------------------------------------------------- SF-D8: countersignature

#[tokio::test]
async fn a_signature_over_a_different_transcript_or_key_is_bad_countersignature() {
    let keys = keys();
    let hole = Hole::accepting();

    // Right key, wrong shard id in the transcript.
    let (out, _) = run(
        Script::Respond(signed_response(&keys, &header(), SHARD + 1)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    assert!(matches!(out, Err(FetchError::BadCountersignature)));

    // Right key, wrong nonce in the transcript.
    let other = RequestHeader::with_nonce([0x11; 32], BlockHeight::from_raw(9_000), [0x5a; 32]);
    let (out, _) = run(
        Script::Respond(signed_response(&keys, &other, SHARD)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    assert!(matches!(out, Err(FetchError::BadCountersignature)));

    // Right transcript, a key that is not the bond record's.
    let imposter = self::keys();
    let (out, _) = run(
        Script::Respond(signed_response(&imposter, &header(), SHARD)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    let err = out.expect_err("refused");
    assert!(matches!(err, FetchError::BadCountersignature), "{err}");
    assert!(!err.retries_same_p());

    assert!(
        hole.shown().is_empty(),
        "content-verify never runs on an unauthenticated body"
    );
}

// ------------------------------------------------------- the content-verify hole

#[tokio::test]
async fn the_hole_refusal_is_typed_apart_and_carries_its_reason() {
    let keys = keys();
    let hole = Hole::refusing("root mismatch");
    let (out, _) = run(
        Script::Respond(signed_response(&keys, &header(), SHARD)),
        Arc::clone(&hole),
        &keys,
    )
    .await;
    match out {
        Err(FetchError::ContentRefused(r)) => assert_eq!(r.reason(), "root mismatch"),
        other => panic!("{other:?}"),
    }
    assert_eq!(hole.shown(), vec![(SHARD, CONTENT.to_vec())]);
}

// -------------------------------------------------------------- SF-D7: the cap

#[tokio::test]
async fn the_in_flight_cap_makes_the_next_fetch_wait_for_a_slot() {
    let keys = keys();
    let stub = Stub::start(Script::Silent).await;
    let client = Arc::new(PFetchClient::with_timeouts(
        stub.proxy,
        Timeouts {
            head: Duration::from_millis(600),
            ..fast()
        },
    ));
    assert_eq!(client.available_slots(), MAX_INFLIGHT);

    let keys = Arc::new(keys);
    let mut held = Vec::new();
    for _ in 0..MAX_INFLIGHT {
        let (c, k) = (Arc::clone(&client), Arc::clone(&keys));
        held.push(tokio::spawn(async move {
            c.fetch(&target(&k), &header(), Hole::accepting()).await
        }));
    }
    // All slots taken by fetches parked on a silent P.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(client.available_slots(), 0);

    // The (N+1)th does not even reach the proxy while the slots are held.
    let (c, k) = (Arc::clone(&client), Arc::clone(&keys));
    let waiter = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let out = c.fetch(&target(&k), &header(), Hole::accepting()).await;
        (started.elapsed(), out)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        stub.seen().len(),
        MAX_INFLIGHT,
        "exactly N exchanges opened"
    );

    // The parked fetches time out (head bound), releasing slots; the waiter
    // then gets one and runs into the same silent P.
    for h in held {
        assert!(matches!(stall(h.await.unwrap()), Stall::HeadTimeout));
    }
    let (waited, out) = waiter.await.unwrap();
    assert!(matches!(stall(out), Stall::HeadTimeout));
    assert!(
        waited >= Duration::from_millis(600),
        "the waiter was admitted only after a slot freed ({waited:?})"
    );
    assert_eq!(client.available_slots(), MAX_INFLIGHT);
}

#[tokio::test]
async fn dropping_a_fetch_releases_its_slot() {
    let keys = keys();
    let stub = Stub::start(Script::Silent).await;
    let client = PFetchClient::with_timeouts(stub.proxy, fast());
    {
        let (t, h) = (target(&keys), header());
        let fut = client.fetch(&t, &h, Hole::accepting());
        let fut = std::pin::pin!(fut);
        // Poll once so the slot is taken and the dial begins.
        let polled = tokio::time::timeout(Duration::from_millis(50), fut).await;
        assert!(polled.is_err(), "the fetch is parked on a silent P");
    }
    assert_eq!(client.available_slots(), MAX_INFLIGHT);
}

/// A hole that parks until told to return, and says when it was entered.
/// The blocking pool runs it, so the park is a real thread block.
struct Parked {
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl ContentVerify for Parked {
    fn verify(&self, _shard_id: u64, _body: &[u8]) -> Result<(), ContentRefused> {
        self.entered.send(()).expect("test is listening");
        let release = self.release.lock().unwrap().take().expect("entered once");
        release.recv().expect("test releases");
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_fetch_mid_verify_keeps_the_slot_until_the_body_is_gone() {
    // The body and the hole outlive a dropped future: `spawn_blocking`
    // does not stop when its handle does. The slot must go with them —
    // otherwise `MAX_INFLIGHT` would bound admissions, not resident
    // bodies, and a caller that cancels during verify could stack bodies.
    let keys = keys();
    let stub = Stub::start(Script::Respond(signed_response(&keys, &header(), SHARD))).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let hole = Arc::new(Parked {
        entered: entered_tx,
        release: Mutex::new(Some(release_rx)),
    });
    let client = Arc::new(PFetchClient::with_timeouts(stub.proxy, fast()));

    let (c, k, v) = (Arc::clone(&client), keys, hole as Arc<dyn ContentVerify>);
    let fetch = tokio::spawn(async move { c.fetch(&target(&k), &header(), v).await });
    // The body has been read and the hole has been entered: verify is
    // running on the pool with the body resident.
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("the hole was entered");
    assert_eq!(client.available_slots(), MAX_INFLIGHT - 1);

    // Cancel the caller. The verify thread is still parked in the hole.
    fetch.abort();
    assert!(fetch.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        client.available_slots(),
        MAX_INFLIGHT - 1,
        "the slot is held by the body, not by the caller"
    );

    // Let the hole return; the body is dropped and the slot comes back.
    release_tx.send(()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while client.available_slots() != MAX_INFLIGHT {
        assert!(
            tokio::time::Instant::now() < deadline,
            "slot not released after the verify finished"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
