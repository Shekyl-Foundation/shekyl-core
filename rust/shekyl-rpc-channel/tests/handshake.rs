// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake through its public API, as a daemon and a client would use
//! it: that it completes and keys a working record channel, and that each
//! message is refused as that message and as nothing finer
//! (`RPC_CHANNEL.md` §4.3).
//!
//! Byte-equality with an independent implementation is elsewhere
//! (`shekyl-rpc-channel-xcheck`). Everything here draws from the operating
//! system, as production does.

use shekyl_rpc_channel::handshake::{
    Client, Daemon, FirstRecord, HandshakeError, PendingSession, StaticKeypair, MESSAGE1_LEN,
    MESSAGE2_LEN, MESSAGE3_OVERHEAD, MESSAGE4_OVERHEAD, MLKEM768_CT_LEN, TAG_LEN,
};
use shekyl_rpc_channel::{NetworkId, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

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
    assert_eq!(message1.len(), MESSAGE1_LEN);
    let daemon = Daemon::new(&NETWORK, &daemon_id)
        .read_message1(&message1)
        .unwrap();
    let (daemon, message2) = daemon.write_message2().unwrap();
    assert_eq!(message2.len(), MESSAGE2_LEN);
    let client = client.read_message2(&message2).unwrap();
    let (client, message3) = client.write_message3(REQUEST).unwrap();
    assert_eq!(message3.len(), MESSAGE3_OVERHEAD + REQUEST.len());
    let (daemon, claimed) = daemon.read_message3(&message3).unwrap();

    // What the daemon decides admission on: an identity, and only that.
    assert_eq!(
        claimed.fingerprint().as_bytes(),
        client_id.public().fingerprint().as_bytes()
    );

    let (pending, message4) = daemon.write_message4(GRANT).unwrap();
    assert_eq!(message4.len(), MESSAGE4_OVERHEAD + GRANT.len());
    let (client, grant) = client.read_message4(&message4).unwrap();
    assert_eq!(grant, GRANT);
    let session_hash = client.handshake_hash();
    assert_eq!(session_hash, pending.handshake_hash());

    // The client's first record is what authenticates it against both
    // primitives, and what releases everything the daemon was not given
    // before: its record halves, the client, and what the client asked for.
    let (mut client_send, mut client_recv) = client.split();
    let record = client_send.seal(b"first request").unwrap();
    let mut session = pending.open_first_record(&record).unwrap();
    assert_eq!(session.first_record, b"first request");
    assert_eq!(session.consumed, record.len());
    assert_eq!(session.request, REQUEST);
    assert_eq!(
        session.client.fingerprint().as_bytes(),
        client_id.public().fingerprint().as_bytes()
    );
    assert_eq!(session.handshake_hash, session_hash);

    let record = session.send.seal(b"first reply").unwrap();
    assert_eq!(client_recv.open_one(&record).unwrap().0, b"first reply");
    let record = client_send.seal(b"second request").unwrap();
    assert_eq!(session.recv.open_one(&record).unwrap().0, b"second request");
}

#[test]
fn two_handshakes_between_the_same_parties_share_nothing() {
    let (client_id, daemon_id) = identities();
    let run = || {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&m1)
            .unwrap();
        let (daemon, m2) = daemon.write_message2().unwrap();
        let client = client.read_message2(&m2).unwrap();
        let (client, m3) = client.write_message3(REQUEST).unwrap();
        let (daemon, _) = daemon.read_message3(&m3).unwrap();
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
    let fields = [MLKEM768_CT_LEN, X25519_PUBLIC_LEN, MLKEM768_EK_LEN, TAG_LEN];
    let positions = one_bit_in_each_field(&fields);
    assert_eq!(positions.len(), 4);

    let mut seen = Vec::new();
    for position in positions {
        let mut bad = good.clone();
        bad[position] ^= 0x01;
        let error = Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&bad)
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
    assert!(Daemon::new(&NETWORK, &daemon_id)
        .read_message1(&good)
        .is_ok());
}

#[test]
fn message_1_for_another_daemon_or_another_network_is_refused() {
    let (client_id, daemon_id) = identities();
    let other_daemon = StaticKeypair::generate().unwrap();

    // Encapsulated to a key this daemon does not hold: decapsulation yields
    // a secret the sender never had, and the tag fails.
    let (_, message1) = Client::start(&NETWORK, &client_id, other_daemon.public()).unwrap();
    assert_eq!(
        Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&message1)
            .err(),
        Some(HandshakeError::Message1)
    );

    // The right daemon, another network: the prologue differs.
    let (_, message1) = Client::start(&OTHER_NETWORK, &client_id, daemon_id.public()).unwrap();
    assert_eq!(
        Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&message1)
            .err(),
        Some(HandshakeError::Message1)
    );
}

#[test]
fn a_changed_message_2_is_refused_as_message_2() {
    let (client_id, daemon_id) = identities();
    let fields = [MLKEM768_CT_LEN, X25519_PUBLIC_LEN, MLKEM768_EK_LEN, TAG_LEN];
    for position in one_bit_in_each_field(&fields) {
        let (client, m1) = Client::start(&NETWORK, &client_id, daemon_id.public()).unwrap();
        let daemon = Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&m1)
            .unwrap();
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
        let daemon = Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&m1)
            .unwrap();
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
        let daemon = Daemon::new(&NETWORK, &daemon_id)
            .read_message1(&m1)
            .unwrap();
        let (daemon, m2) = daemon.write_message2().unwrap();
        let client = client.read_message2(&m2).unwrap();
        let (client, m3) = client.write_message3(REQUEST).unwrap();
        let (daemon, _) = daemon.read_message3(&m3).unwrap();
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
    assert!(Daemon::new(&NETWORK, &impostor_id)
        .read_message1(&m1)
        .is_err());

    // And a message 2 from a different handshake does not open.
    let (other_client, other_m1) =
        Client::start(&NETWORK, &client_id, impostor_id.public()).unwrap();
    let (_, other_m2) = Daemon::new(&NETWORK, &impostor_id)
        .read_message1(&other_m1)
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
/// and the client's two record halves.
fn through_message_4(
    client_id: &StaticKeypair,
    daemon_id: &StaticKeypair,
) -> (
    PendingSession,
    shekyl_noise::SendHalf,
    shekyl_noise::RecvHalf,
) {
    let (client, m1) = Client::start(&NETWORK, client_id, daemon_id.public()).unwrap();
    let daemon = Daemon::new(&NETWORK, daemon_id).read_message1(&m1).unwrap();
    let (daemon, m2) = daemon.write_message2().unwrap();
    let client = client.read_message2(&m2).unwrap();
    let (client, m3) = client.write_message3(REQUEST).unwrap();
    let (daemon, _claimed) = daemon.read_message3(&m3).unwrap();
    let (pending, m4) = daemon.write_message4(GRANT).unwrap();
    let (client, _grant) = client.read_message4(&m4).unwrap();
    let (send, recv) = client.split();
    (pending, send, recv)
}

/// §4.1, §6.2: until the client's first record opens, the daemon holds a
/// pending session and nothing it could serve with. That the halves, the
/// client and the request are *unreachable* before then is a property of
/// the type, shown by the examples on `PendingSession` that must not
/// compile. This shows the other half: what does and does not release them.
#[test]
fn only_a_first_record_from_the_client_releases_the_session() {
    let (client_id, daemon_id) = identities();

    // Bytes that are not a record at all.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    assert!(matches!(
        pending.open_first_record(&[0xa5; 64]),
        Err(FirstRecord::Refused)
    ));

    // A real record, changed in transit.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let mut record = send.seal(b"first request").unwrap();
    let last = record.len() - 1;
    record[last] ^= 0x01;
    assert!(matches!(
        pending.open_first_record(&record),
        Err(FirstRecord::Refused)
    ));

    // A real record from another session of the same client: whoever
    // completed *this* handshake has to be the one who sends it.
    let (pending, _, _) = through_message_4(&client_id, &daemon_id);
    let (_, mut other_send, _) = through_message_4(&client_id, &daemon_id);
    let record = other_send.seal(b"first request").unwrap();
    assert!(matches!(
        pending.open_first_record(&record),
        Err(FirstRecord::Refused)
    ));

    // The daemon's own sending direction is not the client's.
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let record = send.seal(b"first request").unwrap();
    let session = pending.open_first_record(&record).unwrap();
    let (other_pending, _, _) = through_message_4(&client_id, &daemon_id);
    let mut daemon_send = session.send;
    let echoed = daemon_send.seal(b"first request").unwrap();
    assert!(matches!(
        other_pending.open_first_record(&echoed),
        Err(FirstRecord::Refused)
    ));
}

/// A record that has not all arrived decides nothing: the session comes
/// back, and the rest of the record then opens it.
#[test]
fn part_of_a_first_record_neither_admits_nor_refuses() {
    let (client_id, daemon_id) = identities();
    let (pending, mut send, _) = through_message_4(&client_id, &daemon_id);
    let record = send.seal(b"first request, arriving in pieces").unwrap();

    let pending = match pending.open_first_record(&[]) {
        Err(FirstRecord::Incomplete(pending)) => pending,
        other => panic!("no bytes: {:?}", other.err()),
    };
    let pending = match pending.open_first_record(&record[..10]) {
        Err(FirstRecord::Incomplete(pending)) => pending,
        other => panic!("ten bytes: {:?}", other.err()),
    };
    let pending = match pending.open_first_record(&record[..record.len() - 1]) {
        Err(FirstRecord::Incomplete(pending)) => pending,
        other => panic!("all but one byte: {:?}", other.err()),
    };
    let session = pending.open_first_record(&record).unwrap();
    assert_eq!(session.first_record, b"first request, arriving in pieces");
    assert_eq!(session.request, REQUEST);
}

/// This crate writes no log line: the claim the module documentation makes
/// about message 1, held at the only place it can be broken, the manifest.
/// A logging dependency here would be the first step to a line that tells
/// one refusal from another.
#[test]
fn the_crate_has_no_logging_dependency() {
    let manifest = include_str!("../Cargo.toml");
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if !in_dependencies || line.starts_with('#') || line.is_empty() {
            continue;
        }
        let name = line.split(['=', ' ']).next().unwrap_or_default();
        assert!(
            !matches!(name, "log" | "tracing" | "slog" | "shekyl-logging"),
            "{name} is a logging crate"
        );
    }
}
