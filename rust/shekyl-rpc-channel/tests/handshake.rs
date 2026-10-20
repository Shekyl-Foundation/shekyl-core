// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake through its public API, as a daemon and a client would use
//! it: that it completes and keys two transport directions, and that each
//! message is refused as that message and as nothing finer
//! (`RPC_CHANNEL.md` §4.3).
//!
//! Byte-equality with an independent implementation is the pinned comparison
//! beside the handshake. Everything here draws from the operating system, as
//! production does.

use shekyl_noise::{Direction, DirectionError};
use shekyl_rpc_channel::budget::HandshakeBudget;
use shekyl_rpc_channel::handshake::{
    Client, Daemon, DaemonReadyForMessage2, FirstMessageRefused, HandshakeError, Message1Admission,
    PendingSession, StaticKeypair, MESSAGE1_LEN, MESSAGE1_WIRE_LEN, MESSAGE2_LEN,
    MESSAGE3_OVERHEAD, MESSAGE4_OVERHEAD, MLKEM768_CT_LEN, TAG_LEN, TRANSPORT_AD,
};
use shekyl_rpc_channel::{NetworkId, MAC1_LEN, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};
use std::time::{Duration, Instant};

/// A budget that never runs out within a test: the whole of a core, an
/// hour's burst.
fn budget() -> HandshakeBudget {
    HandshakeBudget::with_share(1_000, Duration::from_secs(3_600), Instant::now())
}

/// Recompute a wire message 1's mac1 after its Noise bytes were changed, as
/// a sender holding the daemon's bundle can, so the change reaches the
/// check after mac1 that it names.
fn remac(daemon: &StaticKeypair, wire: &mut [u8]) {
    let (noise, mac1) = wire.split_at_mut(MESSAGE1_LEN);
    mac1.copy_from_slice(&daemon.public().mac1(noise));
}

/// Read message 1 on a budget that does not run out. Busy is a test failure:
/// these tests are about the handshake, and the budget is not what they spend.
fn read1(daemon: &StaticKeypair, message: &[u8]) -> Result<DaemonReadyForMessage2, HandshakeError> {
    match Daemon::new(&NETWORK, daemon).read_message1(message, &budget(), Instant::now()) {
        Ok(Message1Admission::Continue(ready)) => Ok(ready),
        Ok(Message1Admission::Busy(_)) => panic!("the test budget admitted this message"),
        Err(error) => Err(error),
    }
}

const NETWORK: NetworkId = [0x17; 16];
const OTHER_NETWORK: NetworkId = [0x18; 16];
const REQUEST: &[u8] = b"what the client asks for";
const GRANT: &[u8] = b"what the daemon grants";

fn identities() -> (StaticKeypair, StaticKeypair) {
    (
        StaticKeypair::generate().expect("client identity"),
        StaticKeypair::generate().expect("daemon identity"),
    )
}

/// Every single-bit flip position worth trying in a message: one in each
/// field, so each of the message's checks is the one that has to catch it.
fn one_bit_in_each_field(fields: &[usize]) -> Vec<usize> {
    let mut at = 0;
    let mut out = Vec::new();
    for length in fields {
        out.push(at + length / 2);
        at += length;
    }
    out
}

#[test]
fn a_handshake_completes_and_keys_a_record_channel() {
    let (client_id, daemon_id) = identities();

    let (client, message1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
    assert_eq!(message1.len(), MESSAGE1_WIRE_LEN);
    let daemon = read1(&daemon_id, &message1).unwrap();
    let (daemon, message2) = daemon.write_message2().unwrap();
    assert_eq!(message2.len(), MESSAGE2_LEN);
    let client = client.read_message2(&message2).unwrap();
    let (client, message3) = client.write_message3(REQUEST).unwrap();
    assert_eq!(message3.len(), MESSAGE3_OVERHEAD + REQUEST.len());
    let daemon = daemon.read_message3(&message3).unwrap();

    // What the daemon decides admission on: a fingerprint, and only that.
    assert_eq!(
        daemon.fingerprint().as_bytes(),
        client_id.public().fingerprint().as_bytes()
    );

    let (pending, message4) = daemon.write_message4(GRANT).unwrap();
    assert_eq!(message4.len(), MESSAGE4_OVERHEAD + GRANT.len());
    let (client, grant) = client.read_message4(&message4).unwrap();
    assert_eq!(grant, GRANT);
    let session_hash = client.handshake_hash();
    assert_eq!(session_hash, pending.handshake_hash());

    // The client's first transport message authenticates it against both
    // primitives, and releases everything the daemon was not given before:
    // its directions, the client, and what the client asked for.
    let (mut client_send, mut client_recv) = client.into_directions();
    let (message, _) = client_send.seal(b"first request", TRANSPORT_AD).unwrap();
    let (mut session, first) = pending.open_first_message(bare(&message)).unwrap();
    assert_eq!(first, b"first request");
    assert_eq!(session.request, REQUEST);
    assert_eq!(
        session.client.fingerprint().as_bytes(),
        client_id.public().fingerprint().as_bytes()
    );
    assert_eq!(session.handshake_hash, session_hash);

    let (reply, _) = session.send.seal(b"first reply", TRANSPORT_AD).unwrap();
    let (opened, _) = client_recv.open(&reply, TRANSPORT_AD).unwrap();
    assert_eq!(opened, b"first reply");
    let (second, _) = client_send.seal(b"second request", TRANSPORT_AD).unwrap();
    let (opened, _) = session.recv.open(&second, TRANSPORT_AD).unwrap();
    assert_eq!(opened, b"second request");
}

#[test]
fn two_handshakes_between_the_same_parties_share_nothing() {
    let (client_id, daemon_id) = identities();
    let run = || {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = read1(&daemon_id, &m1).unwrap();
        let (daemon, m2) = daemon.write_message2().unwrap();
        let client = client.read_message2(&m2).unwrap();
        let (client, m3) = client.write_message3(REQUEST).unwrap();
        let daemon = daemon.read_message3(&m3).unwrap();
        let (_, m4) = daemon.write_message4(GRANT).unwrap();
        let (client, _) = client.read_message4(&m4).unwrap();
        (client.handshake_hash(), m1, m3)
    };
    let (first_hash, first_m1, first_m3) = run();
    let (second_hash, second_m1, second_m3) = run();
    assert_ne!(first_hash, second_hash);
    assert_ne!(first_m1, second_m1);
    // Message 3 carries the same static bundle both times, sealed: the two
    // must not be recognisable as the same client.
    assert_ne!(first_m3, second_m3);
}

/// §4.3: every way message 1 can be wrong is one error.
///
/// This holds the *answer* uniform. That the *time* to it does not separate
/// a rejected ciphertext from an accepted one rests elsewhere: on RT-P4's
/// measurement of decapsulation, and on the two cases running the same code
/// after it, up to the tag check that fails for both. A ciphertext ML-KEM
/// rejects (a flipped bit in `skem`) and a ciphertext it accepts under a tag
/// that does not verify (a flipped bit in the tag) are the two cases the
/// design names; the other fields are here so that no check has its own
/// answer.
#[test]
fn every_fault_in_message_1_is_the_same_error() {
    let (client_id, daemon_id) = identities();
    let (_, good) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
    // The Noise message's four fields, each re-signed so the change reaches
    // its own check; then the mac1 itself, not re-signed.
    let fields = [
        MLKEM768_CT_LEN,
        X25519_PUBLIC_LEN,
        MLKEM768_EK_LEN,
        TAG_LEN,
        MAC1_LEN,
    ];
    let positions = one_bit_in_each_field(&fields);
    assert_eq!(positions.len(), 5);

    let mut seen = Vec::new();
    for position in positions {
        let mut bad = good.clone();
        bad[position] ^= 0x01;
        if position < MESSAGE1_LEN {
            remac(&daemon_id, &mut bad);
        }
        let error = read1(&daemon_id, &bad)
            .err()
            .expect("a changed message 1 is refused");
        seen.push((position, error, format!("{error}"), format!("{error:?}")));
    }
    for (position, error, display, debug) in &seen {
        assert_eq!(*error, HandshakeError::Message1, "byte {position}");
        assert_eq!(display, &seen[0].2, "byte {position}: what is shown");
        assert_eq!(debug, &seen[0].3, "byte {position}: what is logged");
    }

    // The control: the unchanged message is accepted.
    assert!(read1(&daemon_id, &good).is_ok());
}

#[test]
fn message_1_for_another_daemon_or_another_network_is_refused() {
    let (client_id, daemon_id) = identities();
    let other_daemon = StaticKeypair::generate().unwrap();

    // Encapsulated to a key this daemon does not hold: decapsulation yields
    // a secret the sender never had, and the tag fails.
    let (_, message1) = Client::start(&NETWORK, &client_id, other_daemon.public()).unwrap();
    assert_eq!(
        read1(&daemon_id, &message1).err(),
        Some(HandshakeError::Message1)
    );

    // The right daemon, another network: the prologue differs.
    let (_, message1) = Client::start(&OTHER_NETWORK, &client_id, daemon_id.public()).unwrap();
    assert_eq!(
        read1(&daemon_id, &message1).err(),
        Some(HandshakeError::Message1)
    );
}

#[test]
fn a_changed_message_2_is_refused_as_message_2() {
    let (client_id, daemon_id) = identities();
    let fields = [MLKEM768_CT_LEN, X25519_PUBLIC_LEN, MLKEM768_EK_LEN, TAG_LEN];
    for position in one_bit_in_each_field(&fields) {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = read1(&daemon_id, &m1).unwrap();
        let (_, mut m2) = daemon.write_message2().unwrap();
        m2[position] ^= 0x01;
        assert_eq!(
            client.read_message2(&m2).err(),
            Some(HandshakeError::Message2),
            "byte {position}"
        );
    }
}

#[test]
fn a_changed_message_3_is_refused_as_message_3() {
    let (client_id, daemon_id) = identities();
    let fields = [
        X25519_PUBLIC_LEN + TAG_LEN,
        MLKEM768_EK_LEN + TAG_LEN,
        REQUEST.len() + TAG_LEN,
    ];
    for position in one_bit_in_each_field(&fields) {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = read1(&daemon_id, &m1).unwrap();
        let (daemon, m2) = daemon.write_message2().unwrap();
        let client = client.read_message2(&m2).unwrap();
        let (_, mut m3) = client.write_message3(REQUEST).unwrap();
        m3[position] ^= 0x01;
        assert_eq!(
            daemon.read_message3(&m3).err(),
            Some(HandshakeError::Message3),
            "byte {position}"
        );
    }
}

#[test]
fn a_changed_or_short_message_4_is_refused_as_message_4() {
    let (client_id, daemon_id) = identities();
    let fields = [MLKEM768_CT_LEN + TAG_LEN, GRANT.len() + TAG_LEN];
    let mut cases: Vec<Option<usize>> = one_bit_in_each_field(&fields)
        .into_iter()
        .map(Some)
        .collect();
    cases.push(None);
    for case in cases {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = read1(&daemon_id, &m1).unwrap();
        let (daemon, m2) = daemon.write_message2().unwrap();
        let client = client.read_message2(&m2).unwrap();
        let (client, m3) = client.write_message3(REQUEST).unwrap();
        let daemon = daemon.read_message3(&m3).unwrap();
        let (_, mut m4) = daemon.write_message4(GRANT).unwrap();
        match case {
            Some(position) => m4[position] ^= 0x01,
            None => m4.truncate(MESSAGE4_OVERHEAD - 1),
        }
        assert_eq!(
            client.read_message4(&m4).err(),
            Some(HandshakeError::Message4),
            "{case:?}"
        );
    }
}

/// A client that pinned one daemon and reached another gets no message 2 it
/// can accept: the answer was keyed to a secret only the pinned daemon has.
#[test]
fn an_impostor_cannot_answer_message_1() {
    let (client_id, daemon_id) = identities();
    let impostor_id = StaticKeypair::generate().unwrap();

    // The impostor cannot read message 1 at all.
    let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
    assert!(read1(&impostor_id, &m1).is_err());

    // And a message 2 from a different handshake does not open.
    let (other_client, other_m1) =
        Client::start(&NETWORK, &client_id, impostor_id.public()).unwrap();
    let (_, other_m2) = read1(&impostor_id, &other_m1)
        .unwrap()
        .write_message2()
        .unwrap();
    assert_eq!(
        client.read_message2(&other_m2).err(),
        Some(HandshakeError::Message2)
    );
    drop(other_client);
}

/// A daemon and a client through message 4: the daemon's pending session,
/// and the client's two transport directions.
fn through_message_4(
    client_id: &StaticKeypair,
    daemon_id: &StaticKeypair,
) -> (PendingSession, Direction, Direction) {
    let (client, m1) = Client::start(&NETWORK, client_id, daemon_id.public()).unwrap();
    let daemon = read1(daemon_id, &m1).unwrap();
    let (daemon, m2) = daemon.write_message2().unwrap();
    let client = client.read_message2(&m2).unwrap();
    let (client, m3) = client.write_message3(REQUEST).unwrap();
    let daemon = daemon.read_message3(&m3).unwrap();
    let (pending, m4) = daemon.write_message4(GRANT).unwrap();
    let (client, _grant) = client.read_message4(&m4).unwrap();
    let (send, recv) = client.into_directions();
    (pending, send, recv)
}

/// The tests' opener: the first message is one bare Noise ciphertext under
/// [`TRANSPORT_AD`]. The channel's record framer will be another opener;
/// this one exists only here.
fn bare(ciphertext: &[u8]) -> impl FnOnce(&mut Direction) -> Result<Vec<u8>, DirectionError> + '_ {
    move |recv| {
        recv.open(ciphertext, TRANSPORT_AD)
            .map(|(plaintext, _)| plaintext)
    }
}

/// The session is released by what the receiving direction did, not by
/// what the opener says. An opener is code the handshake does not own: the
/// record framer, or a mistake. Whatever it returns, a direction that has
/// opened no ciphertext has authenticated nobody.
#[test]
fn an_opener_that_opened_nothing_is_refused_whatever_it_returns() {
    let (client_id, daemon_id) = identities();

    // Returns Ok without touching the direction.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    assert!(matches!(
        pending.open_first_message(|_recv| Ok::<_, ()>("authenticated, honest")),
        Err(FirstMessageRefused)
    ));

    // Tries, fails, and says Ok anyway. A failed tag is not an open.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    assert!(matches!(
        pending.open_first_message(|recv| {
            assert!(recv.open(&[0xa5; 64], TRANSPORT_AD).is_err());
            assert!(recv.open(&[0x5a; 64], TRANSPORT_AD).is_err());
            Ok::<_, ()>(())
        }),
        Err(FirstMessageRefused)
    ));

    // Opens the real first message and then reports failure: refused too.
    // Both conditions are required, and the session is not handed out on
    // the direction's count alone.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let (message, _) = send.seal(b"first request", TRANSPORT_AD).unwrap();
    assert!(matches!(
        pending.open_first_message(|recv| {
            recv.open(&message, TRANSPORT_AD).unwrap();
            Err::<(), _>("the framing after it was wrong")
        }),
        Err(FirstMessageRefused)
    ));

    // The control: the same message, opened and reported as opened.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let (message, _) = send.seal(b"first request", TRANSPORT_AD).unwrap();
    let (session, first) = pending.open_first_message(bare(&message)).unwrap();
    assert_eq!(first, b"first request");
    assert_eq!(session.recv.opened(), 1);
    assert_eq!(session.send.opened(), 0);
}

/// The count says a direction opened a ciphertext; it does not say which
/// session's. An opener holds the receiving direction by `&mut`, so it can
/// put another session's direction in its place, one that has already
/// opened. The pending session must refuse that: the direction it gets back
/// must carry its own handshake hash, which `into_directions` stamps.
#[test]
fn a_direction_from_another_session_does_not_release_this_one() {
    let (client_id, daemon_id) = identities();

    // Session B, completed: its receiving direction has opened a message.
    let (pending_b, mut send_b, _) = through_message_4(&client_id, &daemon_id);
    let (message_b, _) = send_b.seal(b"b's first request", TRANSPORT_AD).unwrap();
    let (session_b, _) = pending_b.open_first_message(bare(&message_b)).unwrap();
    let mut borrowed = session_b.recv;
    assert_eq!(borrowed.opened(), 1);

    // Session A: the opener swaps B's direction in and opens nothing of A's.
    let (pending_a, _, _) = through_message_4(&client_id, &daemon_id);
    assert!(matches!(
        pending_a.open_first_message(|recv| {
            core::mem::swap(recv, &mut borrowed);
            Ok::<_, ()>(())
        }),
        Err(FirstMessageRefused)
    ));

    // Session A again: the opener opens A's own first message, then swaps
    // B's direction in. The direction it hands back is still not A's.
    let (pending_a, mut send_a, _) = through_message_4(&client_id, &daemon_id);
    let (message_a, _) = send_a.seal(b"a's first request", TRANSPORT_AD).unwrap();
    assert!(matches!(
        pending_a.open_first_message(|recv| {
            recv.open(&message_a, TRANSPORT_AD).unwrap();
            core::mem::swap(recv, &mut borrowed);
            Ok::<_, ()>(())
        }),
        Err(FirstMessageRefused)
    ));
}

/// §4.1, §6.2: until the client's first transport message opens, the daemon
/// holds a pending session and nothing it could serve with. That the
/// directions, the client and the request are unreachable before then is a
/// property of the type, shown by the examples on `PendingSession` that
/// must not compile. This shows the other half: what does and does not
/// release them.
#[test]
fn only_the_clients_first_message_releases_the_session() {
    let (client_id, daemon_id) = identities();

    // Bytes that are not a transport message at all.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    assert!(matches!(
        pending.open_first_message(bare(&[0xa5; 64])),
        Err(FirstMessageRefused)
    ));

    // A real message, changed in transit.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let (mut message, _) = send.seal(b"first request", TRANSPORT_AD).unwrap();
    let last = message.len() - 1;
    message[last] ^= 0x01;
    assert!(matches!(
        pending.open_first_message(bare(&message)),
        Err(FirstMessageRefused)
    ));

    // A real message from another session of the same client: whoever
    // completed *this* handshake has to be the one who sends it.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    let (_, mut other_send, _) = through_message_4(&client_id, &daemon_id);
    let (message, _) = other_send.seal(b"first request", TRANSPORT_AD).unwrap();
    assert!(matches!(
        pending.open_first_message(bare(&message)),
        Err(FirstMessageRefused)
    ));

    // The daemon's own sending direction is not the client's.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let (message, _) = send.seal(b"first request", TRANSPORT_AD).unwrap();
    let (mut session, _) = pending.open_first_message(bare(&message)).unwrap();
    let (other_pending, _, _) = through_message_4(&client_id, &daemon_id);
    let (echoed, _) = session.send.seal(b"first request", TRANSPORT_AD).unwrap();
    assert!(matches!(
        other_pending.open_first_message(bare(&echoed)),
        Err(FirstMessageRefused)
    ));
}

/// A ciphertext that is not a whole transport message does not open, and
/// the session is consumed: there is no second try with the rest of the
/// bytes. Framing belongs to a later slice.
#[test]
fn a_short_first_message_is_refused_and_the_session_is_consumed() {
    let (client_id, daemon_id) = identities();
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let (message, _) = send
        .seal(b"first request, arriving in pieces", TRANSPORT_AD)
        .unwrap();
    let Err(error) = pending.open_first_message(bare(&message[..message.len() - 1])) else {
        panic!("a short message opened");
    };
    assert_eq!(
        error.to_string(),
        "the first transport message was not accepted"
    );
    assert_eq!(format!("{error:?}"), "FirstMessageRefused");
}

/// This crate writes no log line. The claim is held where it can be broken:
/// the production sources, and every key in the manifest.
#[test]
fn the_crate_writes_no_log_line() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/handshake.rs"),
        include_str!("../src/identity.rs"),
    ];
    for source in sources {
        for (number, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for needle in [
                "println!",
                "eprintln!",
                "dbg!",
                "log::",
                "tracing::",
                "slog::",
            ] {
                assert!(!code.contains(needle), "line {}: {needle}", number + 1);
            }
        }
    }
    let manifest = include_str!("../Cargo.toml");
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line.split(['=', ' ']).next().unwrap_or_default();
        assert!(
            !matches!(key, "log" | "tracing" | "slog" | "shekyl-logging"),
            "{key} is a logging crate"
        );
    }
}
