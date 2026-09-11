// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P2, as tests. Each carries the prediction it was pre-registered with
//! (`RPC_TRANSPORT_POSTURE.md` §7.1); a failure is the prediction being wrong,
//! and the sheet names what that costs (RT-4 is re-ranked).
//!
//! The server's counters are the load-bearing oracle: every refusal has its
//! own counter, and each probe asserts the **complete tally** — the one axis
//! it expects at exactly 1, every other axis at 0, the generic error counter
//! at 0, and the handler hits it expects — so a refusal filed under the wrong
//! axis, or counted twice, is red. The client's error is asserted where the
//! client's view *is* the claim (probes 2, 4, 7). Every dial is bounded: a
//! refusal is an error, not a hang, and a hang is this file's failure to
//! report, not CI's.
//!
//! # Coverage boundary (rule 50: necessary, not sufficient)
//!
//! These bite against: a wrong server pin (through the hand-written dial and
//! through hyper-rustls); an un-enrolled client key; a missing client
//! certificate; an enrolled certificate replayed without its key; a peer that
//! connects and never speaks. They do **not** cover: certificate-parsing edge
//! cases (one parser, rustls's own, decides both the pin and the signature —
//! that agreement is by construction, not observed here); ticket resumption
//! bypassing the allowlist (tickets are off by construction; no probe turns
//! them on to watch the verifier be skipped); forward secrecy (holds by rustls
//! construction — `psk_dhe_ke` only, no static key exchange — and no edit to
//! this crate could make an assertion of it go red, so none is made); HTTP
//! semantics above the handshake beyond one `GET /`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::{AlertDescription, ClientConfig};
use shekyl_rt_p2_spike::{
    client_config, client_config_replaying, client_config_without_identity, dial, dial_via_hyper,
    pin_error_in_chain, pin_error_of, rustls_error_in, serve, DialError, Dialed, HyperDialError,
    Identity, PinError, Served,
};

/// Longer than any legitimate exchange here and longer than
/// `HANDSHAKE_TIMEOUT`, so a probe that waits on the server reaping a peer
/// still concludes inside it.
const DEADLINE: Duration = Duration::from_secs(8);

fn ids() -> (Identity, Identity, Identity) {
    (
        Identity::generate("wallet-host").expect("server identity"),
        Identity::generate("laptop").expect("enrolled client"),
        Identity::generate("stranger").expect("un-enrolled client"),
    )
}

async fn serve_for(server: &Identity, laptop: &Identity) -> Served {
    serve(server, BTreeSet::from([laptop.fingerprint]))
        .await
        .expect("serve")
}

/// The hand-written dial, bounded: a refusal is an error, never a hang.
async fn dial_within(
    addr: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<Dialed, DialError> {
    tokio::time::timeout(DEADLINE, dial(addr, config))
        .await
        .expect("a dial must conclude within the deadline — a refusal is an error, not a hang")
}

/// The hyper-rustls dial, bounded likewise.
async fn hyper_within(
    addr: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<String, HyperDialError> {
    tokio::time::timeout(DEADLINE, dial_via_hyper(addr, config))
        .await
        .expect("a hyper dial must conclude within the deadline")
}

/// Wait until `counter` reaches `expected`, or fail after the deadline.
/// Polling rather than a fixed sleep: the server task records a refusal on
/// its own schedule, and "as long as it takes, up to a limit" does not flake
/// on a loaded runner the way "exactly 100 ms" does.
async fn await_count(counter: &AtomicUsize, expected: usize, what: &str) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while counter.load(Ordering::SeqCst) < expected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: expected {expected}, still {} after {DEADLINE:?}",
            counter.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The refusal axes, each one counter on the server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Axis {
    ByUs,
    ByPeer,
    Possession,
    Timeout,
}

const AXES: [Axis; 4] = [Axis::ByUs, Axis::ByPeer, Axis::Possession, Axis::Timeout];

fn counter_for(served: &Served, axis: Axis) -> &AtomicUsize {
    match axis {
        Axis::ByUs => &served.refused_by_us,
        Axis::ByPeer => &served.refused_by_peer,
        Axis::Possession => &served.possession_failures,
        Axis::Timeout => &served.handshake_timeouts,
    }
}

/// The complete server-side tally every probe asserts: `refusal` (if any) is
/// **exactly** 1 — the `== 1` after the `>= 1` wait rules out a double count
/// — every other axis and the generic error counter are 0, and the handler
/// saw exactly `hits` requests.
async fn assert_tally(served: &Served, refusal: Option<Axis>, hits: usize) {
    if let Some(axis) = refusal {
        await_count(counter_for(served, axis), 1, &format!("{axis:?} refusals")).await;
    }
    for axis in AXES {
        let want = usize::from(Some(axis) == refusal);
        assert_eq!(
            counter_for(served, axis).load(Ordering::SeqCst),
            want,
            "{axis:?}: expected {want} with refusal = {refusal:?}"
        );
    }
    assert_eq!(
        served.accept_errors.load(Ordering::SeqCst),
        0,
        "a refusal is a verdict, not a generic accept error"
    );
    assert_eq!(served.hits.load(Ordering::SeqCst), hits, "handler hits");
}

/// What a refused client may observe after its own Finished (TLS 1.3: the
/// server's verdict lands after `connect()` returns). On Linux loopback the
/// queued alert is read before the RST the orphaned server socket provokes;
/// Windows and macOS discard the receive queue on RST, so there the client
/// sees a reset or EOF instead. Either is "refused, and told so by the
/// transport"; the server's counter is what proves *why*.
fn refusal_reached_client(io: &std::io::Error, alert: AlertDescription) {
    use std::io::ErrorKind as K;
    let tls = rustls_error_in(io);
    let reset = matches!(
        io.kind(),
        K::ConnectionReset | K::UnexpectedEof | K::BrokenPipe
    );
    assert!(
        matches!(tls, Some(rustls::Error::AlertReceived(ref a)) if *a == alert) || reset,
        "expected the {alert:?} alert or a reset, got {io:?}"
    );
}

/// 1. Correct pins connect, both directions — and the posture is what RT-4
///    says: TLS 1.3 read back from the connection, early data not configured.
///    (Forward secrecy is not asserted: see the file doc.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_correct_pins_round_trip_under_tls13() {
    let (server, laptop, _) = ids();
    let served = serve_for(&server, &laptop).await;
    let config = client_config(&laptop, server.fingerprint).expect("client config");
    assert!(!config.enable_early_data, "RT-5: early data must be off");

    let dialed = dial_within(served.addr, config)
        .await
        .expect("correct pins must connect");
    assert_eq!(dialed.body, "ok");
    assert_eq!(dialed.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_tally(&served, None, 1).await;
}

/// 2. The bite check. A wrong server pin is rejected **at the handshake**,
///    before any application byte — the error is the handshake variant, which
///    by construction precedes the first application write — carrying the
///    typed mismatch with both fingerprints; the server saw zero requests and
///    one refusal *by the peer*.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_wrong_server_pin_is_refused_before_any_application_byte() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    // The laptop was "paired" with some other host's key.
    let config = client_config(&laptop, stranger.fingerprint).expect("client config");

    let err = dial_within(served.addr, config)
        .await
        .expect_err("a wrong server pin must not connect");
    let DialError::Handshake(io) = &err else {
        panic!("rejection must be at the handshake, before any application write: {err:?}");
    };
    let tls = rustls_error_in(io).expect("a pin refusal carries the rustls error");
    match pin_error_of(&tls) {
        Some(PinError::ServerPinMismatch { expected, found }) => {
            assert_eq!(*expected, stranger.fingerprint);
            assert_eq!(*found, server.fingerprint);
        }
        other => panic!("expected a typed ServerPinMismatch, got {other:?} in {tls}"),
    }
    assert_tally(&served, Some(Axis::ByPeer), 0).await;
}

/// 3a. A client whose key is not enrolled is refused by the server — after
///     the client's own Finished, so deterministically `AfterHandshake` — and
///     the client learns it from the transport rather than a silent hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_unenrolled_client_is_refused_server_side() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let config = client_config(&stranger, server.fingerprint).expect("client config");

    let err = dial_within(served.addr, config)
        .await
        .expect_err("an un-enrolled client must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::CertificateUnknown);
    assert_tally(&served, Some(Axis::ByUs), 0).await;
}

/// 3b. Client authentication is mandatory, observed: a client presenting no
///     certificate is refused on the same axis as an un-enrolled one. The edit
///     that turns this red is `client_auth_mandatory()` returning `false` —
///     which every other probe would survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_certificateless_client_is_refused_server_side() {
    let (server, laptop, _) = ids();
    let served = serve_for(&server, &laptop).await;
    let config = client_config_without_identity(server.fingerprint).expect("client config");

    let err = dial_within(served.addr, config)
        .await
        .expect_err("a client without a certificate must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::CertificateRequired);
    assert_tally(&served, Some(Axis::ByUs), 0).await;
}

/// 4. Distinguishability (rule 82): a pin mismatch and a dead network are
///    different values, so guidance can differ — "do not retry into this" vs
///    "check the connection". (Probe 2 already pins the mismatch's contents;
///    this one asserts only the axis that separates the two.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_pin_mismatch_is_not_a_connection_failure() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let mismatch = dial_within(
        served.addr,
        client_config(&laptop, stranger.fingerprint).expect("config"),
    )
    .await
    .expect_err("mismatch");

    // Port 0 is never listened on, so connect() refuses deterministically
    // (ECONNREFUSED here) — unlike "bind, read the port, drop, dial", where
    // another process can take the port in the gap.
    let dead = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
    let refused = dial_within(
        dead,
        client_config(&laptop, server.fingerprint).expect("config"),
    )
    .await
    .expect_err("nothing listens there");

    assert!(matches!(refused, DialError::Connect(_)), "{refused:?}");
    let DialError::Handshake(io) = &mismatch else {
        panic!("a mismatch is a handshake failure: {mismatch:?}");
    };
    let tls = rustls_error_in(io).expect("the mismatch carries the rustls error");
    let pin =
        pin_error_of(&tls).expect("the mismatch must carry the typed PinError a UI can branch on");
    assert!(
        pin.to_string().contains("do not retry"),
        "the message must carry the remedy, not just the fact: {pin}"
    );
}

/// 5. Proof of possession. An enrolled certificate presented by a client that
///    holds a different key passes the allowlist and fails CertificateVerify;
///    the server files it on its own axis, not as a policy refusal, and serves
///    nothing. The edit that turns this red is `verify_tls13_signature`
///    returning `HandshakeSignatureValid::assertion()` — the null check the
///    module doc names as the real misuse of a custom verifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_replayed_certificate_without_its_key_is_refused() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let config = client_config_replaying(&laptop.cert, &stranger, server.fingerprint)
        .expect("client config");

    let err = dial_within(served.addr, config)
        .await
        .expect_err("a replayed certificate must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::DecryptError);
    assert_tally(&served, Some(Axis::Possession), 0).await;
}

/// 6. A connected peer that never sends a ClientHello holds only its own
///    handshake task: a correctly pinned client is served while it is still
///    connected, and the silent peer is reaped under `HANDSHAKE_TIMEOUT` —
///    counted once, on its own axis, with the good client's one hit the only
///    other entry in the tally. The ordering is a count, not a clock: when
///    the good dial completes, `handshake_timeouts` is still 0, so the
///    silent peer was still connected (not yet reaped) while another client
///    was served. The edit that turns the first half red is awaiting the
///    handshake inline in the accept loop (the good dial then cannot
///    complete before the reap); the second half, removing the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_silent_peer_does_not_block_the_next_client() {
    let (server, laptop, _) = ids();
    let served = serve_for(&server, &laptop).await;
    let silent = tokio::net::TcpStream::connect(served.addr)
        .await
        .expect("connect without speaking");

    let dialed = dial_within(
        served.addr,
        client_config(&laptop, server.fingerprint).expect("config"),
    )
    .await
    .expect("correct pins must connect while a silent peer is connected");
    assert_eq!(dialed.body, "ok");
    assert_eq!(
        served.handshake_timeouts.load(Ordering::SeqCst),
        0,
        "the silent peer must still be connected (not yet reaped) when the good client \
         has been served — that is the ordering claim"
    );

    assert_tally(&served, Some(Axis::Timeout), 1).await;
    drop(silent);
}

/// 7a. The production connector accepts this posture: the same `ClientConfig`
///     — custom verifier, client identity, TLS 1.3 only, no resumption —
///     installed into hyper-rustls's `HttpsConnector` under hyper-util's
///     client round-trips `GET /`. The edit that turns this red is the
///     connector refusing the verifier or the identity (the re-rank trigger
///     §7.1 named), or the client identity not being presented (the server
///     would refuse by us).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_hyper_rustls_connector_round_trips_with_the_same_config() {
    let (server, laptop, _) = ids();
    let served = serve_for(&server, &laptop).await;
    let body = hyper_within(
        served.addr,
        client_config(&laptop, server.fingerprint).expect("config"),
    )
    .await
    .expect("correct pins through hyper-rustls must connect");
    assert_eq!(body, "ok");
    assert_tally(&served, None, 1).await;
}

/// 7b. The typed verdict survives hyper's error chain: a wrong server pin
///     through hyper-rustls is a `ServerPinMismatch` recoverable from the
///     top-level error, with zero handler hits and one refusal by the peer —
///     so a UI built on the production client can still say "do not retry".
///     The edit that turns this red is flattening the connector error to a
///     string anywhere in the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_wrong_server_pin_is_typed_through_hyper_rustls() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let err = hyper_within(
        served.addr,
        client_config(&laptop, stranger.fingerprint).expect("config"),
    )
    .await
    .expect_err("a wrong server pin must not connect through hyper either");
    match pin_error_in_chain(&err) {
        Some(PinError::ServerPinMismatch { expected, found }) => {
            assert_eq!(expected, stranger.fingerprint);
            assert_eq!(found, server.fingerprint);
        }
        other => panic!("expected a typed ServerPinMismatch in the chain, got {other:?} in {err}"),
    }
    assert_tally(&served, Some(Axis::ByPeer), 0).await;
}
