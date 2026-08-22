// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P2, as tests. Each carries the prediction it was pre-registered with
//! (`RPC_TRANSPORT_POSTURE.md` §7.1); a failure is the prediction being wrong,
//! and the sheet names what that costs (RT-4 is re-ranked).
//!
//! The server's counters are the load-bearing oracle: every refusal has its
//! own counter, and each probe requires exactly one to be 1 and the rest 0,
//! so a refusal filed under the wrong axis is red. The client's error is
//! asserted where the client's view *is* the claim (probes 2 and 4).
//!
//! # Coverage boundary (rule 50: necessary, not sufficient)
//!
//! These bite against: a wrong server pin; an un-enrolled client key; a
//! missing client certificate; an enrolled certificate replayed without its
//! key; a peer that connects and never speaks. They do **not** cover:
//! certificate-parsing edge cases (one parser, rustls's own, decides both the
//! pin and the signature — that agreement is by construction, not observed
//! here); ticket resumption bypassing the allowlist (tickets are off by
//! construction; no probe turns them on to watch the verifier be skipped);
//! forward secrecy (holds by rustls construction — `psk_dhe_ke` only, no
//! static key exchange — and no edit to this crate could make an assertion of
//! it go red, so none is made); anything above the handshake.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::AlertDescription;
use shekyl_rt_p2_spike::{
    client_config, client_config_replaying, client_config_without_identity, dial, pin_error_of,
    rustls_error_in, serve, DialError, Identity, PinError, Served, HANDSHAKE_TIMEOUT,
};

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

/// Wait until `counter` reaches `expected`, or fail after a generous bound.
/// Polling rather than a fixed sleep: the server task records a refusal on
/// its own schedule, and "as long as it takes, up to a limit" does not flake
/// on a loaded runner the way "exactly 100 ms" does.
async fn await_count(counter: &AtomicUsize, expected: usize, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::SeqCst) < expected {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: expected {expected}, still {} after 5s",
            counter.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The refusal axes, in the order [`tally`] reports them.
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

fn tally(served: &Served) -> Vec<(Axis, usize)> {
    AXES.iter()
        .map(|&a| (a, counter_for(served, a).load(Ordering::SeqCst)))
        .collect()
}

/// The server-side standard every refusal probe meets: the named axis is
/// **exactly** 1 (the `== 1` after the `>= 1` wait rules out a double count),
/// every other axis and the generic error counter are 0, and the handler was
/// never reached.
async fn assert_exactly_one_refusal(served: &Served, axis: Axis) {
    await_count(counter_for(served, axis), 1, &format!("{axis:?} refusals")).await;
    for (a, n) in tally(served) {
        let want = usize::from(a == axis);
        assert_eq!(
            n, want,
            "{a:?}: the refusal must be filed under {axis:?} alone"
        );
    }
    assert_eq!(
        served.accept_errors.load(Ordering::SeqCst),
        0,
        "a refusal is a verdict, not a generic accept error"
    );
    assert_eq!(
        served.hits.load(Ordering::SeqCst),
        0,
        "no application data may reach the handler"
    );
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

    let dialed = dial(served.addr, config)
        .await
        .expect("correct pins must connect");
    assert_eq!(dialed.body, "ok");
    assert_eq!(dialed.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(served.hits.load(Ordering::SeqCst), 1);
    for (a, n) in tally(&served) {
        assert_eq!(n, 0, "{a:?}: nothing was refused");
    }
    assert_eq!(served.accept_errors.load(Ordering::SeqCst), 0);
}

/// 2. The bite check. A wrong server pin is rejected **at the handshake**,
///    before the client writes anything — the error is the handshake variant
///    carrying the typed mismatch with both fingerprints, and the server saw
///    zero requests and one refusal *by the peer*.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_wrong_server_pin_is_refused_before_any_byte_is_written() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    // The laptop was "paired" with some other host's key.
    let config = client_config(&laptop, stranger.fingerprint).expect("client config");

    let err = dial(served.addr, config)
        .await
        .expect_err("a wrong server pin must not connect");
    let DialError::Handshake(io) = &err else {
        panic!("rejection must be at the handshake, before any write: {err:?}");
    };
    let tls = rustls_error_in(io).expect("a pin refusal carries the rustls error");
    match pin_error_of(&tls) {
        Some(PinError::ServerPinMismatch { expected, found }) => {
            assert_eq!(*expected, stranger.fingerprint);
            assert_eq!(*found, server.fingerprint);
        }
        other => panic!("expected a typed ServerPinMismatch, got {other:?} in {tls}"),
    }
    assert_exactly_one_refusal(&served, Axis::ByPeer).await;
}

/// 3a. A client whose key is not enrolled is refused by the server — after
///     the client's own Finished, so deterministically `AfterHandshake` — and
///     the client learns it from the transport rather than a silent hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_unenrolled_client_is_refused_server_side() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let config = client_config(&stranger, server.fingerprint).expect("client config");

    let err = dial(served.addr, config)
        .await
        .expect_err("an un-enrolled client must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::CertificateUnknown);
    assert_exactly_one_refusal(&served, Axis::ByUs).await;
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

    let err = dial(served.addr, config)
        .await
        .expect_err("a client without a certificate must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::CertificateRequired);
    assert_exactly_one_refusal(&served, Axis::ByUs).await;
}

/// 4. Distinguishability (rule 82): a pin mismatch and a dead network are
///    different values, so guidance can differ — "do not retry into this" vs
///    "check the connection". (Probe 2 already pins the mismatch's contents;
///    this one asserts only the axis that separates the two.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_pin_mismatch_is_not_a_connection_failure() {
    let (server, laptop, stranger) = ids();
    let served = serve_for(&server, &laptop).await;
    let mismatch = dial(
        served.addr,
        client_config(&laptop, stranger.fingerprint).expect("config"),
    )
    .await
    .expect_err("mismatch");

    // Port 0 is never listened on, so connect() refuses deterministically
    // (ECONNREFUSED here) — unlike "bind, read the port, drop, dial", where
    // another process can take the port in the gap.
    let dead = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
    let refused = dial(
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

    let err = dial(served.addr, config)
        .await
        .expect_err("a replayed certificate must not be served");
    let DialError::AfterHandshake(io) = &err else {
        panic!("TLS 1.3: the server's verdict lands after connect(); got {err:?}");
    };
    refusal_reached_client(io, AlertDescription::DecryptError);
    assert_exactly_one_refusal(&served, Axis::Possession).await;
}

/// 6. A connected peer that never sends a ClientHello holds only its own
///    handshake task: a correctly pinned client is served while it is still
///    connected, and the silent peer is reaped under [`HANDSHAKE_TIMEOUT`].
///    The edit that turns the first half red is awaiting the handshake inline
///    in the accept loop; the second half, removing the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_silent_peer_does_not_block_the_next_client() {
    let (server, laptop, _) = ids();
    let served = serve_for(&server, &laptop).await;
    let silent = tokio::net::TcpStream::connect(served.addr)
        .await
        .expect("connect without speaking");

    let dialed = tokio::time::timeout(
        HANDSHAKE_TIMEOUT / 2,
        dial(
            served.addr,
            client_config(&laptop, server.fingerprint).expect("config"),
        ),
    )
    .await
    .expect("the good client must be served while the silent peer is still connected")
    .expect("correct pins must connect");
    assert_eq!(dialed.body, "ok");
    assert_eq!(served.hits.load(Ordering::SeqCst), 1);

    await_count(&served.handshake_timeouts, 1, "reaped silent peers").await;
    assert_eq!(served.accept_errors.load(Ordering::SeqCst), 0);
    drop(silent);
}
