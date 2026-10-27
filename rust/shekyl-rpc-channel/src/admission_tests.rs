// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Message 1's admission: mac1, the encapsulation-key check, the replay
//! window and the handshake budget (`RPC_CHANNEL.md` §4.3).

use super::support::{accepted_message1, low_order_points, read1, remac, uses, NETWORK};
use super::*;

/// §4.3: message 1 with a low-order `e` is refused, as message 1.
///
/// This cannot tell the refusal from the tag failing: the sender made
/// its tag with a different `e`, so the tag would fail anyway. That a
/// low-order point is never mixed is what
/// `a_low_order_point_yields_nothing_to_mix` shows, on the one function
/// every Diffie-Hellman token goes through.
#[test]
fn message_1_with_a_low_order_ephemeral_is_refused() {
    for point in low_order_points() {
        let (daemon, mut message1) = accepted_message1();
        message1[MLKEM768_CT_LEN..MLKEM768_CT_LEN + X25519_PUBLIC_LEN].copy_from_slice(&point);
        remac(&daemon, &mut message1);
        assert_eq!(
            read1(&daemon, &message1).err(),
            Some(HandshakeError::Message1)
        );
    }
}

/// §4.3: the client's ephemeral encapsulation key is input-checked, and
/// a key that fails the check is refused before either long-term key is
/// used, and before the replay window or the budget. The good message
/// afterwards still takes the one admission that budget held.
#[test]
fn a_malformed_encapsulation_key_is_refused_before_any_long_term_key_is_used() {
    let (daemon, good) = accepted_message1();
    let mut bad = good.clone();
    let ek = MLKEM768_CT_LEN + X25519_PUBLIC_LEN;
    bad[ek..ek + MLKEM768_EK_LEN].fill(0xff);
    remac(&daemon, &mut bad);

    let now = Instant::now();
    let one = HandshakeBudget::with_share(
        1_000,
        std::time::Duration::from_nanos(crate::budget::HANDSHAKE_DAEMON_CPU_NANOS),
        now,
    );
    assert_eq!(one.burst_admissions(), 1);

    let before = uses();
    assert_eq!(
        Daemon::new(&NETWORK, &daemon)
            .read_message1(&bad, &one, now)
            .err(),
        Some(HandshakeError::Message1)
    );
    assert_eq!(uses(), before, "no long-term key touched a malformed key");
    let mut bad_mac1 = [0u8; MAC1_LEN];
    bad_mac1.copy_from_slice(&bad[MESSAGE1_LEN..]);
    assert!(
        !one.remembers(&bad_mac1),
        "a malformed key is not remembered"
    );

    let before = uses();
    assert!(
        matches!(
            Daemon::new(&NETWORK, &daemon)
                .read_message1(&good, &one, now)
                .unwrap(),
            Message1Admission::Continue(_)
        ),
        "the one admission is still there"
    );
    assert_eq!(uses(), before + 2, "decapsulation and `es`, once each");
}

/// A message of the wrong length is refused on its length alone.
#[test]
fn a_message_1_of_the_wrong_length_uses_no_long_term_key() {
    let (daemon, good) = accepted_message1();
    let long = [good.as_slice(), &[0]].concat();
    for wrong in [
        &good[..0],
        &good[..MESSAGE1_LEN],
        &good[..MESSAGE1_WIRE_LEN - 1],
        long.as_slice(),
    ] {
        let before = uses();
        assert_eq!(read1(&daemon, wrong).err(), Some(HandshakeError::Message1));
        assert_eq!(uses(), before);
    }
}

/// §4.3, mac1: a stranger without the daemon's bundle cannot make it
/// use a long-term key, or spend from its budget. Three strangers: random
/// bytes; a client's genuine message 1 made for another daemon; and a
/// genuine message 1 for this daemon whose mac1 was changed. Each is
/// refused with nothing used and nothing paid, and the control after
/// them is admitted by a budget that holds exactly one admission.
#[test]
fn a_strangers_message_1_is_refused_before_any_long_term_key_is_used() {
    let (daemon, good) = accepted_message1();
    let (other, _) = accepted_message1();
    let client = StaticKeypair::generate().unwrap();
    let (_, for_other) = Client::start(&NETWORK, &client, other.public()).unwrap();
    let random: Vec<u8> = (0..MESSAGE1_WIRE_LEN)
        .map(|i| u8::try_from(i * 31 % 251).unwrap())
        .collect();
    let mut wrong_mac = good.clone();
    wrong_mac[MESSAGE1_WIRE_LEN - 1] ^= 1;

    let now = Instant::now();
    let one = HandshakeBudget::with_share(
        1_000,
        std::time::Duration::from_nanos(crate::budget::HANDSHAKE_DAEMON_CPU_NANOS),
        now,
    );
    assert_eq!(one.burst_admissions(), 1);
    for stranger in [&random, &for_other, &wrong_mac] {
        let before = uses();
        assert_eq!(
            Daemon::new(&NETWORK, &daemon)
                .read_message1(stranger, &one, now)
                .err(),
            Some(HandshakeError::Message1)
        );
        assert_eq!(
            uses(),
            before,
            "no long-term key touched a stranger's message"
        );
    }
    let before = uses();
    assert!(
        Daemon::new(&NETWORK, &daemon)
            .read_message1(&good, &one, now)
            .is_ok(),
        "the budget's one admission is still there: no stranger spent it"
    );
    assert_eq!(uses(), before + 2);
}

/// §4.3, ruled 2026-10-20: a message 1 that passed mac1 and finds the
/// budget empty is answered "busy", before any long-term key is used,
/// and the client that sent it recognises the answer. A stranger's
/// message 1 is still dropped silently, budget or no budget.
#[test]
fn an_exhausted_budget_answers_busy_before_any_long_term_key_is_used() {
    let daemon = StaticKeypair::generate().unwrap();
    let client = StaticKeypair::generate().unwrap();
    let (waiting, good) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let now = Instant::now();
    let none = HandshakeBudget::with_share(1_000, std::time::Duration::ZERO, now);
    assert_eq!(none.burst_admissions(), 0);
    let before = uses();
    let Ok(Message1Admission::Busy(reply)) =
        Daemon::new(&NETWORK, &daemon).read_message1(&good, &none, now)
    else {
        panic!("a bundle holder's message 1 on an empty budget is answered busy");
    };
    assert_eq!(uses(), before);
    assert!(
        waiting.is_busy(&reply),
        "the client recognises its own busy reply"
    );

    let mut stranger = good.clone();
    stranger[MESSAGE1_WIRE_LEN - 1] ^= 1;
    assert_eq!(
        Daemon::new(&NETWORK, &daemon)
            .read_message1(&stranger, &none, now)
            .err(),
        Some(HandshakeError::Message1),
        "a mac1 failure stays silent, even on an empty budget"
    );
    assert_eq!(uses(), before);
}

/// A captured message 1 is admitted once. The replay is silent, spends
/// nothing and uses no long-term key, and the budget's remaining
/// admission is still there for a different message.
#[test]
fn a_replayed_message_1_is_silent_and_spends_nothing() {
    let daemon = StaticKeypair::generate().unwrap();
    let client = StaticKeypair::generate().unwrap();
    let (_, first) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let (_, second) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let now = Instant::now();
    let two = HandshakeBudget::with_share(
        1_000,
        std::time::Duration::from_nanos(crate::budget::HANDSHAKE_DAEMON_CPU_NANOS * 2),
        now,
    );
    assert_eq!(two.burst_admissions(), 2);

    let before = uses();
    assert!(matches!(
        Daemon::new(&NETWORK, &daemon)
            .read_message1(&first, &two, now)
            .unwrap(),
        Message1Admission::Continue(_)
    ));
    assert_eq!(uses(), before + 2);

    let before = uses();
    assert_eq!(
        Daemon::new(&NETWORK, &daemon)
            .read_message1(&first, &two, now)
            .err(),
        Some(HandshakeError::Message1),
        "the same bytes again are a refusal, not a second handshake"
    );
    assert_eq!(uses(), before, "a replay touches no long-term key");

    let before = uses();
    assert!(
        matches!(
            Daemon::new(&NETWORK, &daemon)
                .read_message1(&second, &two, now)
                .unwrap(),
            Message1Admission::Continue(_)
        ),
        "the replay left the second admission for a new message 1"
    );
    assert_eq!(uses(), before + 2);
}

/// Only the daemon's busy reply to this very message 1 counts as busy:
/// not random bytes, not a reply authenticated under another bundle,
/// not the reply to an earlier attempt, not a reply of the wrong length.
/// A forged "busy" is a connection closed without an answer.
#[test]
fn a_forged_busy_reply_is_not_busy() {
    let daemon = StaticKeypair::generate().unwrap();
    let other = StaticKeypair::generate().unwrap();
    let client = StaticKeypair::generate().unwrap();
    let busy_for = |wire: &[u8], who: &StaticKeypair| {
        let mut mac1 = [0u8; MAC1_LEN];
        mac1.copy_from_slice(&wire[MESSAGE1_LEN..]);
        who.public().busy_reply(&mac1)
    };
    let (earlier, earlier_wire) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let (waiting, wire) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let genuine = busy_for(&wire, &daemon);
    assert!(waiting.is_busy(&genuine));
    assert!(earlier.is_busy(&busy_for(&earlier_wire, &daemon)));

    assert!(!waiting.is_busy(&[0u8; BUSY_LEN]), "zeros");
    assert!(!waiting.is_busy(&[0xa5; BUSY_LEN]), "other bytes");
    assert!(
        !waiting.is_busy(&busy_for(&wire, &other)),
        "authenticated under a bundle other than the daemon's"
    );
    assert!(
        !waiting.is_busy(&busy_for(&earlier_wire, &daemon)),
        "the reply to an earlier message 1"
    );
    let mut flipped = genuine;
    flipped[BUSY_LEN - 1] ^= 1;
    assert!(!waiting.is_busy(&flipped), "one bit changed");
    assert!(!waiting.is_busy(&genuine[..BUSY_LEN - 1]), "short");
    let mut long = genuine.to_vec();
    long.push(0);
    assert!(!waiting.is_busy(&long), "long");
    assert!(!waiting.is_busy(&[]), "nothing");
}

/// §4.3, the budget under a flood. A session is established first. Then
/// a bundle holder sends message 1s with valid mac1s and broken tags, as
/// fast as it likes, for two simulated seconds. The long-term keys are
/// used only as often as the budget pays for, the CPU those admissions
/// stand for stays within the share of the window plus the burst, and
/// the established session still carries records both ways afterwards.
///
/// The budget here is 1 % of a core, not the ruled 25 %, so that the
/// flood is short in a debug build; the arithmetic is the same, and the
/// budget module tests the ruled figures.
#[test]
fn a_flood_of_valid_mac1_messages_is_held_to_the_budget() {
    let daemon = StaticKeypair::generate().unwrap();
    let client = StaticKeypair::generate().unwrap();
    let t0 = Instant::now();
    let share = 10;
    let burst = std::time::Duration::from_secs(1);
    let budget = HandshakeBudget::with_share(share, burst, t0);

    // The established session.
    let (c, m1) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
    let Ok(Message1Admission::Continue(d)) =
        Daemon::new(&NETWORK, &daemon).read_message1(&m1, &budget, t0)
    else {
        panic!("the first handshake is admitted");
    };
    let (d, m2) = d.write_message2().unwrap();
    let c = c.read_message2(&m2).unwrap();
    let (c, m3) = c.write_message3(b"request").unwrap();
    let d = d.read_message3(&m3).unwrap();
    let (pending, m4) = d.write_message4(b"grant").unwrap();
    let (c, _) = c.read_message4(&m4).unwrap();
    let (mut client_send, mut client_recv) = c.into_directions();
    let (first, _) = client_send.seal(b"first", TRANSPORT_AD).unwrap();
    let (mut session, _) = pending
        .open_first_message(|recv| recv.open(&first, TRANSPORT_AD).map(|(p, _)| p))
        .unwrap();

    // The flood: valid mac1s over broken tags, spread over two seconds.
    let flood: Vec<Vec<u8>> = (0..40)
        .map(|_| {
            let (_, mut m) = Client::start(&NETWORK, &client, daemon.public()).unwrap();
            m[MESSAGE1_LEN - 1] ^= 1;
            remac(&daemon, &mut m);
            m
        })
        .collect();
    let window = std::time::Duration::from_secs(2);
    let before = uses();
    let mut admitted = 0u64;
    for (i, m) in flood.iter().enumerate() {
        let now = t0 + window * u32::try_from(i).unwrap() / 40;
        let used = uses();
        let result = Daemon::new(&NETWORK, &daemon).read_message1(m, &budget, now);
        let was_admitted = uses() > used;
        match result {
            Err(HandshakeError::Message1) => {
                assert!(was_admitted, "admitted, then the tag failed")
            }
            Ok(Message1Admission::Busy(_)) => {
                assert!(!was_admitted, "refused, and answered busy")
            }
            other => panic!("a broken tag never authenticates: {other:?}"),
        }
        admitted += u64::from(was_admitted);
    }
    assert_eq!(
        uses() - before,
        2 * admitted,
        "two long-term operations per admission"
    );
    let ns = |d: std::time::Duration| u64::try_from(d.as_nanos()).unwrap();
    let allowed = (ns(window) + ns(burst)) * share / 1_000;
    let spent = (admitted + 1) * crate::budget::HANDSHAKE_DAEMON_CPU_NANOS;
    assert!(
        spent <= allowed,
        "{spent} ns of handshakes admitted against {allowed}"
    );
    assert!(
        admitted < 40,
        "the flood was held, not passed: {admitted} of 40"
    );
    assert!(
        admitted > 0,
        "and the budget still admits what it has earned"
    );

    // The established session is untouched.
    let (sealed, _) = client_send.seal(b"after the flood", TRANSPORT_AD).unwrap();
    let (opened, _) = session.recv.open(&sealed, TRANSPORT_AD).unwrap();
    assert_eq!(opened, b"after the flood");
    let (reply, _) = session.send.seal(b"still here", TRANSPORT_AD).unwrap();
    let (opened, _) = client_recv.open(&reply, TRANSPORT_AD).unwrap();
    assert_eq!(opened, b"still here");
}
