// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P2, as tests. Each carries the prediction it was pre-registered with
//! (`RPC_TRANSPORT_POSTURE.md` §7.1); a failure is the prediction being wrong,
//! and the sheet names what that costs (RT-4 is re-ranked).

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use shekyl_rt_p2_spike::{
    client_config, dial, pin_error_of, rustls_error_in, serve, DialError, Identity, PinError,
};

fn ids() -> (Identity, Identity, Identity) {
    (
        Identity::generate("wallet-host").expect("server identity"),
        Identity::generate("laptop").expect("enrolled client"),
        Identity::generate("stranger").expect("un-enrolled client"),
    )
}

/// Wait until `counter` reaches `expected`, or fail after a generous bound.
/// Polling rather than a fixed sleep: the server task records a rejection on
/// its own schedule, and "as long as it takes, up to a limit" does not flake
/// on a loaded runner the way "exactly 100 ms" does.
async fn await_count(counter: &std::sync::atomic::AtomicUsize, expected: usize, what: &str) {
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

/// 1. Correct pins connect, both directions — and the posture is what RT-4
///    says: TLS 1.3, an (EC)DHE group agreed, no early data configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_correct_pins_round_trip_under_tls13_with_ecdhe() {
    let (server, laptop, _) = ids();
    let served = serve(&server, BTreeSet::from([laptop.fingerprint]))
        .await
        .expect("serve");
    let config = client_config(&laptop, server.fingerprint).expect("client config");
    assert!(!config.enable_early_data, "RT-5: early data must be off");

    let dialed = dial(served.addr, config)
        .await
        .expect("correct pins must connect");
    assert_eq!(dialed.body, "ok");
    assert_eq!(dialed.version, Some(rustls::ProtocolVersion::TLSv1_3));
    assert!(
        dialed.kx_group.is_some(),
        "an (EC)DHE group must have been negotiated — forward secrecy is a property of \
         the handshake that happened"
    );
    assert_eq!(served.hits.load(Ordering::SeqCst), 1);
    assert_eq!(served.rejected.load(Ordering::SeqCst), 0);
}

/// 2. The bite check. A wrong server pin is rejected **at the handshake**,
///    before the client writes anything — the error is the handshake variant,
///    and the server saw zero requests and one rejected handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_wrong_server_pin_is_refused_before_any_byte_is_written() {
    let (server, laptop, stranger) = ids();
    let served = serve(&server, BTreeSet::from([laptop.fingerprint]))
        .await
        .expect("serve");
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
    await_count(&served.rejected, 1, "refused handshakes").await;
    assert_eq!(
        served.hits.load(Ordering::SeqCst),
        0,
        "no application data may reach the handler"
    );
    assert_eq!(
        served.rejected.load(Ordering::SeqCst),
        1,
        "the server must have seen exactly one refused handshake"
    );
}

/// 3. A client whose key is not enrolled is refused by the server: zero
///    handler hits, one rejected handshake, and the client learns it as a TLS
///    alert rather than a silent hang or a generic socket error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_unenrolled_client_is_refused_server_side() {
    let (server, laptop, stranger) = ids();
    let served = serve(&server, BTreeSet::from([laptop.fingerprint]))
        .await
        .expect("serve");
    let config = client_config(&stranger, server.fingerprint).expect("client config");

    let err = dial(served.addr, config)
        .await
        .expect_err("an un-enrolled client must not be served");
    // TLS 1.3: the client's Finished precedes the server's verdict, so the
    // refusal can arrive either during the handshake or on the first I/O.
    let tls = match &err {
        DialError::Handshake(io) | DialError::AfterHandshake(io) => rustls_error_in(io),
        DialError::Connect(_) => None,
    };
    assert!(
        matches!(tls, Some(rustls::Error::AlertReceived(_))),
        "the client must learn of the refusal as a TLS alert, got {err:?}"
    );
    await_count(&served.rejected, 1, "refused handshakes").await;
    assert_eq!(
        served.hits.load(Ordering::SeqCst),
        0,
        "handler must see nothing"
    );
    assert_eq!(served.rejected.load(Ordering::SeqCst), 1);
}

/// 4. Distinguishability (rule 82): a pin mismatch and a dead network are
///    different values, so guidance can differ — "do not retry into this" vs
///    "check the connection".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2_pin_mismatch_is_not_a_connection_failure() {
    let (server, laptop, stranger) = ids();
    let served = serve(&server, BTreeSet::from([laptop.fingerprint]))
        .await
        .expect("serve");
    let mismatch = dial(
        served.addr,
        client_config(&laptop, stranger.fingerprint).expect("config"),
    )
    .await
    .expect_err("mismatch");

    // A port nothing listens on.
    let free = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let dead = free.local_addr().expect("addr");
    drop(free);
    let refused = dial(
        dead,
        client_config(&laptop, server.fingerprint).expect("config"),
    )
    .await
    .expect_err("nothing listens there");

    assert!(matches!(mismatch, DialError::Handshake(_)));
    assert!(matches!(refused, DialError::Connect(_)));
    let DialError::Handshake(io) = &mismatch else {
        unreachable!()
    };
    let tls = rustls_error_in(io).expect("the mismatch carries the rustls error");
    assert!(
        pin_error_of(&tls).is_some(),
        "the mismatch must carry the typed PinError a UI can branch on"
    );
    let shown = pin_error_of(&tls)
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        shown.contains("do not retry"),
        "the message must carry the remedy, not just the fact: {shown}"
    );
}
