// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client against an in-crate stub that is both the SOCKS5 proxy and
//! `P`: it accepts the SOCKS handshake, records what the client asked the
//! proxy to resolve, reads the HTTP request, and then plays one scripted
//! response. Every `SF-D6` outcome is driven from here, over a two-entry
//! `shard_frame` body the expectation knows row by row.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ServingEndpoint;
use shekyl_archival_retention::{pass_delivery_digest, shard_view_hash, ArchivalTx};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_types::{ArchivalLength, BlockHeight, ShardId, TxHash, SHARD_LENGTH};
use shekyl_wire::shard_frame::{encode_frame, rows_of, FrameTx, VarintFault};
use shekyl_wire::TxidParts;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::{
    ContentMismatch, DiscardTxs, ExpectedShard, FetchError, FetchTarget, FrameError, Malformed,
    NextMove, PFetchClient, RequestHeader, Stall, Timeouts, TxSink, VerifiedShard, VerifiedTx,
    MAX_INFLIGHT, SIGNATURE_ENVELOPE_LEN,
};

const SHARD: ShardId = ShardId::from_raw(17);

/// `(pqc_auth_count, pqc_auths, prunable)` of one fixture transaction.
type Entry = (u64, Vec<u8>, Vec<u8>);

/// Entry 0: one `pqc_auths` authorization and a prunable region with
/// structure. Entry 1: prunable only.
fn entries() -> [Entry; 2] {
    let prunable_a: Vec<u8> = (0..300u16)
        .map(|i| u8::try_from(i % 251).expect("modulus"))
        .collect();
    [
        (1, vec![0x11; 40], prunable_a),
        (0, Vec::new(), vec![0x22; 128]),
    ]
}

fn frame_txs(entries: &[Entry]) -> Vec<FrameTx<'_>> {
    entries
        .iter()
        .map(|(count, pqc, prunable)| FrameTx {
            pqc_auth_count: *count,
            pqc_auths: pqc,
            prunable,
        })
        .collect()
}

fn hashes() -> [TxHash; 2] {
    [
        TxHash::from_bytes([0xaa; 32]),
        TxHash::from_bytes([0xbb; 32]),
    ]
}

/// The retained rows for [`entries`], as a requester holds them.
fn rows() -> Vec<TxidParts> {
    let entries = entries();
    frame_txs(&entries)
        .iter()
        .zip(hashes())
        .map(|(tx, hash)| {
            let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(tx);
            TxidParts {
                hash,
                pqc_auth_hash,
                prunable_hash,
                archival_len,
            }
        })
        .collect()
}

/// The fixture body: the two entries framed.
fn body() -> Vec<u8> {
    encode_frame(&frame_txs(&entries()))
}

/// The expectation: shard 17, the two rows, placed so the range closes the
/// shard (its cumulative-before is `18·W − archival_len`).
fn expected() -> ExpectedShard {
    let rows = rows();
    let total: u64 = rows.iter().map(|r| r.archival_len.to_raw()).sum();
    let cum_before = (SHARD.to_raw() + 1) * SHARD_LENGTH.to_raw() - total;
    ExpectedShard::new(SHARD, ArchivalLength::from_raw(cum_before), rows).expect("closed")
}

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

/// What the sink records of one transaction:
/// `(index, txid, pqc_auth_count, pqc_auths, prunable)`.
type Shown = (u64, TxHash, u64, Vec<u8>, Vec<u8>);

/// A sink that records every transaction it was handed.
#[derive(Default)]
struct Sink {
    shown: Mutex<Vec<Shown>>,
}

impl Sink {
    fn new() -> Arc<Self> {
        Arc::default()
    }
    fn shown(&self) -> Vec<Shown> {
        self.shown.lock().unwrap().clone()
    }
    /// The indices handed over, in order.
    fn indices(&self) -> Vec<u64> {
        self.shown().into_iter().map(|t| t.0).collect()
    }
}

impl TxSink for Sink {
    fn accept(&self, tx: &VerifiedTx<'_>) {
        self.shown.lock().unwrap().push((
            tx.index,
            tx.parts.hash,
            tx.pqc_auth_count,
            tx.pqc_auths.to_vec(),
            tx.prunable.to_vec(),
        ));
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

/// `P`'s countersignature for a response whose body is `body`: over the
/// header, the shard id, and the digest of `body` under the header's nonce.
fn sign(keys: &Keys, header: &RequestHeader, shard_id: u64, body: &[u8]) -> HybridSignature {
    HybridEd25519MlDsa
        .sign(
            &keys.secret,
            SCHEME_DOMAIN_ATTESTATION,
            &header.transcript(shard_id, &pass_delivery_digest(header.nonce(), body)),
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
    out.extend_from_slice(content);
    out.extend_from_slice(envelope);
    out
}

fn head_only(status_line: &str, headers: &str) -> Vec<u8> {
    format!("{status_line}\r\n{headers}\r\n\r\n").into_bytes()
}

/// A 200 carrying `body`, countersigned by `keys` for `shard_id` over
/// exactly those bytes — what a conforming `P` sends.
fn signed_body(keys: &Keys, header: &RequestHeader, shard_id: u64, body: &[u8]) -> Vec<u8> {
    let sig = sign(keys, header, shard_id, body)
        .to_canonical_bytes()
        .unwrap();
    assert_eq!(sig.len(), SIGNATURE_ENVELOPE_LEN);
    ok_response(&sig, body)
}

/// [`signed_body`] over the fixture [`body`] for [`SHARD`].
fn signed_response(keys: &Keys, header: &RequestHeader) -> Vec<u8> {
    signed_body(keys, header, SHARD.to_raw(), &body())
}

async fn run(
    script: Script,
    sink: Arc<dyn TxSink>,
    keys: &Keys,
) -> (Result<VerifiedShard, FetchError>, Vec<Seen>) {
    let stub = Stub::start(script).await;
    let client = PFetchClient::with_timeouts(stub.proxy, fast());
    let out = client
        .fetch(&target(keys), &header(), &expected(), sink)
        .await;
    // Let the stub finish recording.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (out, stub.seen())
}

fn content_refused(r: Result<VerifiedShard, FetchError>) -> ContentMismatch {
    match r {
        Err(FetchError::ContentRefused(m)) => m,
        Err(other) => panic!("not content-refused: {other}"),
        Ok(_) => panic!("fetched"),
    }
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
    let sink = Sink::new();
    let (out, seen) = run(
        Script::Respond(signed_response(&keys, &header())),
        sink.clone(),
        &keys,
    )
    .await;
    let shard = out.expect("fetched");
    assert_eq!(shard.shard_id(), SHARD);
    assert_eq!(shard.tx_count(), 2);
    assert_eq!(shard.archival_len(), expected().archival_len());
    assert_eq!(
        shard.signature().to_canonical_bytes().unwrap().len(),
        SIGNATURE_ENVELOPE_LEN
    );
    // The sink was handed both entries, in order, with the bytes the frame
    // carried and the row each matched.
    let entries = entries();
    let hashes = hashes();
    assert_eq!(
        sink.shown(),
        vec![
            (0, hashes[0], 1, entries[0].1.clone(), entries[0].2.clone()),
            (1, hashes[1], 0, entries[1].1.clone(), entries[1].2.clone()),
        ]
    );
    // The digest handed on for the pass record is this client's own
    // recomputation over every body byte it received, frame included.
    assert_eq!(
        shard.delivery_digest(),
        &pass_delivery_digest(header().nonce(), &body())
    );
    // The view hash is the SV-D fold over the verified transactions.
    let view = shard_view_hash(
        SHARD,
        entries
            .iter()
            .zip(&hashes)
            .map(|((_, pqc, prunable), txid)| ArchivalTx {
                txid,
                prunable,
                pqc_auths: pqc,
            }),
    );
    assert_eq!(shard.view_hash(), view);

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
            "GET /shard/{} HTTP/1.1\r\nshekyl-pass-request: {}\r\n\r\n",
            SHARD.to_raw(),
            header().wire_value()
        )
    );
}

// ------------------------------------------------------------------ SF-D6: miss

#[tokio::test]
async fn a_404_is_a_miss_and_is_not_retried_on_the_same_p() {
    let keys = keys();
    let sink = Sink::new();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 404 Not Found",
            "content-type: application/octet-stream\r\ncontent-length: 0",
        )),
        sink.clone(),
        &keys,
    )
    .await;
    let err = out.expect_err("miss");
    assert!(matches!(err, FetchError::Miss), "{err}");
    assert!(!err.retries_same_p());
    assert!(
        sink.shown().is_empty(),
        "the sink is not handed anything on a miss"
    );
}

#[tokio::test]
async fn a_400_is_rejected_and_earns_one_retry_with_a_fresh_anchor() {
    // `P` judged the request invalid. From this client that means the
    // anchor missed `P`'s gate, which skew on either side can cause — so
    // the first one is neither a miss nor `P`'s failure: the scheduler
    // names the same `P` once more with a freshly derived anchor.
    let keys = keys();
    let sink = Sink::new();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 400 Bad Request",
            "content-type: application/octet-stream\r\ncontent-length: 0",
        )),
        sink.clone(),
        &keys,
    )
    .await;
    let err = out.expect_err("rejected");
    assert!(matches!(err, FetchError::Rejected), "{err}");
    assert_eq!(err.next_move(false), NextMove::RetryFreshAnchor);
    assert!(
        !err.retries_same_p(),
        "the same header would be refused again"
    );
    assert!(sink.shown().is_empty());
}

#[test]
fn a_second_400_is_a_failed_read() {
    // `P`'s gate sits within ±L of `P`'s own height. A `P` that refuses a
    // freshly derived anchor too is itself out of step, and that is `P`'s
    // failure — not a miss, and not a third attempt.
    assert_eq!(FetchError::Rejected.next_move(true), NextMove::FailedRead);
    // The flag belongs to the 400 alone.
    for seen in [false, true] {
        assert_eq!(FetchError::Miss.next_move(seen), NextMove::NotHeld);
        assert_eq!(FetchError::Unsigned.next_move(seen), NextMove::FailedRead);
        assert_eq!(
            FetchError::Unavailable.next_move(seen),
            NextMove::FailedRead
        );
        assert_eq!(
            FetchError::BadCountersignature.next_move(seen),
            NextMove::FailedRead
        );
        assert_eq!(
            FetchError::Stall(Stall::HeadTimeout).next_move(seen),
            NextMove::RetrySameHeader
        );
    }
}

#[tokio::test]
async fn a_400_with_a_body_is_not_the_contract() {
    let keys = keys();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 400 Bad Request",
            "content-type: application/octet-stream\r\ncontent-length: 5",
        )),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentLength);
}

#[tokio::test]
async fn a_503_is_a_failed_read_with_no_retry() {
    // `P` could not serve and says the fault is its own. A held shard never
    // 404s, so this is not a miss; and it is a completed answer, so it is
    // not retried.
    let keys = keys();
    let sink = Sink::new();
    let two = "content-type: application/octet-stream\r\ncontent-length: 0";
    let (out, _) = run(
        Script::Respond(head_only("HTTP/1.1 503 Service Unavailable", two)),
        sink.clone(),
        &keys,
    )
    .await;
    let err = out.expect_err("unavailable");
    assert!(matches!(err, FetchError::Unavailable), "{err}");
    assert_eq!(err.next_move(false), NextMove::FailedRead);
    assert!(!err.retries_same_p());
    assert!(sink.shown().is_empty());

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 503 Service Unavailable",
            "content-type: application/octet-stream\r\ncontent-length: 5",
        )),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentLength);
}

#[tokio::test]
async fn a_body_closed_with_the_refusal_trailer_is_a_failed_read() {
    // `P` sent the whole body and wrote the refusal trailer where the
    // signature goes. That is `P` saying it did not sign: a failed read,
    // no retry. The body streamed through the row checks on the way — the
    // sink saw content the rows vouch for — but no pass record follows.
    let keys = keys();
    let sink = Sink::new();
    let trailer = [shekyl_curve_tree::serving_route::REFUSAL_TRAILER_BYTE; SIGNATURE_ENVELOPE_LEN];
    let (out, _) = run(
        Script::Respond(ok_response(&trailer, &body())),
        sink.clone(),
        &keys,
    )
    .await;
    let err = out.expect_err("unsigned");
    assert!(matches!(err, FetchError::Unsigned), "{err}");
    assert_eq!(err.next_move(false), NextMove::FailedRead);
    assert!(!err.retries_same_p());
    assert_eq!(sink.indices(), vec![0, 1]);

    // One byte off the trailer is not a refusal. It is an envelope that is
    // not a signature either, which is a `P` off the contract.
    let mut near = trailer;
    near[SIGNATURE_ENVELOPE_LEN - 1] = 0xFE;
    let (out, _) = run(
        Script::Respond(ok_response(&near, &body())),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Envelope);
}

#[tokio::test]
async fn a_good_response_cut_exactly_at_the_frames_end_is_a_stall() {
    // The attack the trailer exists for. A relay on the circuit counts
    // bytes against a public frame length and cuts a good, signed response
    // exactly where the signature would begin. The client must read that
    // as transport — retried with the same header — and never as `P`
    // declining to sign. So must a cut one byte either side of it.
    let keys = keys();
    let whole = signed_response(&keys, &header());
    let frame_end = whole.len() - SIGNATURE_ENVELOPE_LEN;
    for cut in [frame_end, frame_end - 1, frame_end + 1, whole.len() - 1] {
        let (out, _) = run(
            Script::Respond(whole[..cut].to_vec()),
            Arc::new(DiscardTxs),
            &keys,
        )
        .await;
        let err = out.expect_err("cut");
        assert!(
            matches!(err, FetchError::Stall(Stall::Truncated { .. })),
            "cut at {cut}: {err}"
        );
        assert_eq!(err.next_move(false), NextMove::RetrySameHeader);
        assert!(err.retries_same_p());
    }
}

#[tokio::test]
async fn a_404_with_a_body_is_not_the_contract() {
    let keys = keys();
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 404 Not Found",
            "content-type: application/octet-stream\r\ncontent-length: 3",
        )),
        Arc::new(DiscardTxs),
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
    let (out, _) = run(Script::Respond(bytes), Arc::new(DiscardTxs), &keys).await;
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
    let mut bytes = signed_response(&keys, &header());
    bytes.extend_from_slice(b"trailer");
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN + body().len()).unwrap();
    let (out, _) = run(Script::Respond(bytes), Arc::new(DiscardTxs), &keys).await;
    assert_eq!(malformed(out), Malformed::Overlength { declared });
}

#[tokio::test]
async fn a_late_trailer_is_caught_on_the_probe_for_the_close() {
    // The body is complete and verifiable; the excess arrives only after
    // the client has it all. The probe that a conforming `P` answers
    // with EOF is answered with a byte instead.
    let keys = keys();
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN + body().len()).unwrap();
    let (out, _) = run(
        Script::RespondThenTrail(signed_response(&keys, &header()), b"x".to_vec()),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Overlength { declared });
}

#[tokio::test]
async fn a_complete_body_with_no_close_is_a_stall() {
    // Every byte arrived; `P` just never hung up. The client cannot call
    // the body final until it sees EOF, and a `P` that goes quiet instead
    // is wedged — a stall, retried like one — not lying.
    let keys = keys();
    let (out, _) = run(
        Script::RespondHoldOpen(signed_response(&keys, &header())),
        Arc::new(DiscardTxs),
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
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Status(500));

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!("{two}\r\nserver: nginx"),
        )),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::HeaderSet);

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            "content-type: text/html\r\ncontent-length: 0",
        )),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentType);

    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            "content-type: application/octet-stream\r\ncontent-length: x",
        )),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::ContentLength);

    let (out, _) = run(Script::EndlessHead, Arc::new(DiscardTxs), &keys).await;
    assert_eq!(malformed(out), Malformed::HeadTooLong);
}

#[tokio::test]
async fn the_body_is_bounded_from_the_head_before_a_byte_is_read() {
    let keys = keys();
    let max = expected().max_response_len();

    // Too short to hold a signature.
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN).unwrap() - 1;
    let (out, _) = run(
        Script::Respond(head_only(
            "HTTP/1.1 200 OK",
            &format!("content-type: application/octet-stream\r\ncontent-length: {declared}"),
        )),
        Arc::new(DiscardTxs),
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
        Arc::new(DiscardTxs),
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
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert!(matches!(stall(out), Stall::Truncated { declared, received: 0 } if declared == max));
}

#[tokio::test]
async fn an_envelope_that_is_not_a_canonical_signature_is_malformed() {
    let keys = keys();
    let (out, _) = run(
        // Not `0xff`: that fill is the refusal trailer, which is `P`
        // speaking and is typed apart.
        Script::Respond(ok_response(&[0xa5u8; SIGNATURE_ENVELOPE_LEN], &body())),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Envelope);
}

#[tokio::test]
async fn a_signature_sent_ahead_of_the_body_is_refused() {
    // The order is the contract: `P` releases the countersignature after
    // the frame, so the client takes it from the body's tail. A response
    // that leads with a perfectly valid signature is a `P` handing out the
    // receipt before the delivery, and it is refused — the signature bytes
    // are read as a frame, which they are not, or the tail is content
    // bytes, not a signature — without the sink ever being handed anything.
    let keys = keys();
    let sink = Sink::new();
    let header = header();
    let body = body();
    let sig = sign(&keys, &header, SHARD.to_raw(), &body)
        .to_canonical_bytes()
        .unwrap();
    let mut leading = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n",
        shekyl_curve_tree::serving_route::CONTENT_TYPE,
        sig.len() + body.len()
    )
    .into_bytes();
    leading.extend_from_slice(&sig);
    leading.extend_from_slice(&body);

    let (out, _) = run(Script::Respond(leading), sink.clone(), &keys).await;
    assert!(
        matches!(
            out,
            Err(FetchError::Malformed(_) | FetchError::BadCountersignature)
        ),
        "a leading signature must not be accepted: {out:?}"
    );
    assert!(sink.shown().is_empty());
}

#[tokio::test]
async fn garbage_with_a_valid_signature_appended_is_refused() {
    // `P` signs the digest of the real body and then sends other bytes of
    // the same length with that signature behind them.
    let keys = keys();
    let body = body();
    let sig = sign(&keys, &header(), SHARD.to_raw(), &body)
        .to_canonical_bytes()
        .unwrap();

    // Bytes that are not a frame are refused where they are read — the
    // first byte is not the frame version — and nothing else is consulted.
    let sink = Sink::new();
    let garbage = vec![0xEEu8; body.len()];
    let (out, _) = run(
        Script::Respond(ok_response(&sig, &garbage)),
        sink.clone(),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Frame(FrameError::Version(0xEE)));
    assert!(sink.shown().is_empty());

    // A well-formed frame with one content byte flipped — the last byte
    // of entry 1's prunable region — behind a signature over the real
    // body. The client hashes what it received, so the signature does not
    // verify, and the mismatch it also found is NOT reported: a mismatch
    // under a bad signature says nothing about `P`'s content. Entry 0 was
    // handed to the sink before the flip was reached; that is the sink's
    // contract (a prefix on a failed fetch), not a leak.
    let sink = Sink::new();
    let mut flipped = body.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let (out, _) = run(
        Script::Respond(ok_response(&sig, &flipped)),
        sink.clone(),
        &keys,
    )
    .await;
    assert!(
        matches!(out, Err(FetchError::BadCountersignature)),
        "{out:?}"
    );
    assert_eq!(sink.indices(), vec![0]);
}

// ----------------------------------------------------------------- SF-D6: stall

#[tokio::test]
async fn every_incomplete_exchange_is_a_stall_that_retries_the_same_p() {
    let keys = keys();

    let (out, _) = run(Script::Silent, Arc::new(DiscardTxs), &keys).await;
    let err = out.expect_err("stall");
    assert!(err.retries_same_p());
    assert!(
        matches!(err, FetchError::Stall(Stall::HeadTimeout)),
        "{err}"
    );

    let (out, _) = run(Script::CloseBeforeHead, Arc::new(DiscardTxs), &keys).await;
    assert!(matches!(stall(out), Stall::ClosedBeforeHead));

    let (out, seen) = run(Script::RefuseConnect, Arc::new(DiscardTxs), &keys).await;
    assert!(matches!(stall(out), Stall::Dial(_)));
    assert_eq!(seen.len(), 1, "the CONNECT reached the proxy");

    // Truncation: the head promises more than the stream carries.
    let mut short = signed_response(&keys, &header());
    short.truncate(short.len() - 5);
    let (out, _) = run(Script::Respond(short), Arc::new(DiscardTxs), &keys).await;
    let declared = u64::try_from(SIGNATURE_ENVELOPE_LEN + body().len()).unwrap();
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
        .fetch(&target(&keys), &header(), &expected(), Arc::new(DiscardTxs))
        .await;
    assert!(matches!(stall(out), Stall::Dial(_)));
}

// ------------------------------------------------------- SF-D8: countersignature

#[tokio::test]
async fn a_signature_over_a_different_transcript_or_key_is_bad_countersignature() {
    let keys = keys();
    let body = body();

    // Right key, wrong shard id in the transcript.
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw() + 1, &body)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert!(matches!(out, Err(FetchError::BadCountersignature)));

    // Right key, wrong nonce in the transcript.
    let other = RequestHeader::with_nonce([0x11; 32], BlockHeight::from_raw(9_000), [0x5a; 32]);
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &other, SHARD.to_raw(), &body)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert!(matches!(out, Err(FetchError::BadCountersignature)));

    // Right transcript, a key that is not the bond record's.
    let imposter = self::keys();
    let (out, _) = run(
        Script::Respond(signed_response(&imposter, &header())),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    let err = out.expect_err("refused");
    assert!(matches!(err, FetchError::BadCountersignature), "{err}");
    assert!(!err.retries_same_p());
}

// --------------------------------------------- SF-D8 amendment: the content check

#[tokio::test]
async fn a_frame_declaring_another_transaction_count_is_content_refused() {
    // `P` serves a well-formed one-entry frame, signed for what it sent.
    // The requester expects two: the count is checked first, the body is
    // drained, and — the signature verifying — the mismatch is `P`'s.
    let keys = keys();
    let sink = Sink::new();
    let entries = entries();
    let one = encode_frame(&frame_txs(&entries[..1]));
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &one)),
        sink.clone(),
        &keys,
    )
    .await;
    let m = content_refused(out);
    assert_eq!(
        m,
        ContentMismatch::TxCount {
            expected: 2,
            declared: 1
        }
    );
    assert!(sink.shown().is_empty());
}

#[tokio::test]
async fn declared_lengths_off_the_row_are_refused_before_the_segments_are_read() {
    // Entry 0's prunable region is one byte short of its row. The lengths
    // are checked before a segment byte is read; the rest is drained and,
    // the signature verifying, the mismatch names the entry.
    let keys = keys();
    let sink = Sink::new();
    let mut entries = entries();
    entries[0].2.pop();
    let short = encode_frame(&frame_txs(&entries));
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &short)),
        sink.clone(),
        &keys,
    )
    .await;
    let rows = rows();
    assert_eq!(
        content_refused(out),
        ContentMismatch::Lengths {
            index: 0,
            expected: rows[0].archival_len,
            pqc_auths_len: 40,
            prunable_len: 299,
        }
    );
    assert!(sink.shown().is_empty());

    // A `pqc_auths` segment declared for a row that has none.
    let mut entries = self::entries();
    entries[1].0 = 1;
    entries[1].1 = vec![0x33; 8];
    entries[1].2.truncate(120);
    let wrong_shape = encode_frame(&frame_txs(&entries));
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &wrong_shape)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(
        content_refused(out),
        ContentMismatch::Lengths {
            index: 1,
            expected: rows[1].archival_len,
            pqc_auths_len: 8,
            prunable_len: 120,
        }
    );
}

#[tokio::test]
async fn a_segment_that_does_not_hash_to_its_row_is_content_refused_by_entry() {
    // `P` signs exactly what it sends, so the countersignature verifies and
    // the refusal is about `P`'s content: the entry whose segment is wrong.
    let keys = keys();

    // Entry 0's `pqc_auths` flipped: nothing reaches the sink.
    let sink = Sink::new();
    let mut entries = entries();
    entries[0].1[3] ^= 0x80;
    let flipped = encode_frame(&frame_txs(&entries));
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &flipped)),
        sink.clone(),
        &keys,
    )
    .await;
    assert_eq!(
        content_refused(out),
        ContentMismatch::PqcAuthHash { index: 0 }
    );
    assert!(sink.shown().is_empty());

    // Entry 1's prunable flipped: entry 0 verified and was handed over;
    // entry 1 was not; the refusal names entry 1.
    let sink = Sink::new();
    let mut entries = self::entries();
    entries[1].2[7] ^= 1;
    let flipped = encode_frame(&frame_txs(&entries));
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &flipped)),
        sink.clone(),
        &keys,
    )
    .await;
    assert_eq!(
        content_refused(out),
        ContentMismatch::PrunableHash { index: 1 }
    );
    assert_eq!(sink.indices(), vec![0]);
}

#[tokio::test]
async fn a_body_that_is_not_the_frame_grammar_is_malformed_where_it_is_read() {
    let keys = keys();
    let body = body();

    // Wrong version byte.
    let mut versioned = body.clone();
    versioned[0] = 2;
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &versioned)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::Frame(FrameError::Version(2)));

    // A non-canonical count varint (`2` written as `0x82 0x00`).
    let mut redundant = vec![body[0], 0x82, 0x00];
    redundant.extend_from_slice(&body[2..]);
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &redundant)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(
        malformed(out),
        Malformed::Frame(FrameError::Varint(VarintFault::NonCanonical))
    );

    // The frame wants more content than the body has ahead of the
    // envelope: `content-length` is honest about the bytes, the frame is
    // not.
    let cut = &body[..body.len() - 3];
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), cut)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::FrameShort);

    // The frame ends with content bytes still ahead of the envelope.
    let mut padded = body.clone();
    padded.extend_from_slice(&[0u8; 3]);
    let (out, _) = run(
        Script::Respond(signed_body(&keys, &header(), SHARD.to_raw(), &padded)),
        Arc::new(DiscardTxs),
        &keys,
    )
    .await;
    assert_eq!(malformed(out), Malformed::FrameLong);
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
            c.fetch(&target(&k), &header(), &expected(), Arc::new(DiscardTxs))
                .await
        }));
    }
    // All slots taken by fetches parked on a silent P.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(client.available_slots(), 0);

    // The (N+1)th does not even reach the proxy while the slots are held.
    let (c, k) = (Arc::clone(&client), Arc::clone(&keys));
    let waiter = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let out = c
            .fetch(&target(&k), &header(), &expected(), Arc::new(DiscardTxs))
            .await;
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
        let (t, h, e) = (target(&keys), header(), expected());
        let fut = client.fetch(&t, &h, &e, Arc::new(DiscardTxs));
        let fut = std::pin::pin!(fut);
        // Poll once so the slot is taken and the dial begins.
        let polled = tokio::time::timeout(Duration::from_millis(50), fut).await;
        assert!(polled.is_err(), "the fetch is parked on a silent P");
    }
    assert_eq!(client.available_slots(), MAX_INFLIGHT);
}

/// A sink that parks on its first entry until told to return, and says
/// when it was entered. The blocking pool runs it, so the park is a real
/// thread block.
struct Parked {
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl TxSink for Parked {
    fn accept(&self, _tx: &VerifiedTx<'_>) {
        let Some(release) = self.release.lock().unwrap().take() else {
            return;
        };
        self.entered.send(()).expect("test is listening");
        release.recv().expect("test releases");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_fetch_mid_check_keeps_the_slot_until_the_entry_is_gone() {
    // The resident entry and the sink call outlive a dropped future:
    // `spawn_blocking` does not stop when its handle does. The slot must go
    // with them — otherwise `MAX_INFLIGHT` would bound admissions, not
    // resident work, and a caller that cancels during a check could stack
    // entries.
    let keys = keys();
    let stub = Stub::start(Script::Respond(signed_response(&keys, &header()))).await;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let sink = Arc::new(Parked {
        entered: entered_tx,
        release: Mutex::new(Some(release_rx)),
    });
    let client = Arc::new(PFetchClient::with_timeouts(stub.proxy, fast()));

    let (c, k, v) = (Arc::clone(&client), keys, sink as Arc<dyn TxSink>);
    let fetch = tokio::spawn(async move { c.fetch(&target(&k), &header(), &expected(), v).await });
    // Entry 0 has been read and the sink has been entered: the check is
    // running on the pool with the entry resident.
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("the sink was entered");
    assert_eq!(client.available_slots(), MAX_INFLIGHT - 1);

    // Cancel the caller. The check thread is still parked in the sink.
    fetch.abort();
    assert!(fetch.await.unwrap_err().is_cancelled());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        client.available_slots(),
        MAX_INFLIGHT - 1,
        "the slot is held by the resident entry, not by the caller"
    );

    // Let the sink return; the entry is dropped and the slot comes back.
    release_tx.send(()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while client.available_slots() != MAX_INFLIGHT {
        assert!(
            tokio::time::Instant::now() < deadline,
            "slot not released after the check finished"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
