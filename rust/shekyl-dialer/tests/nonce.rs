// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The self-connection nonces and the wake spacing.

use shekyl_dialer::{next_wake_nanos, HandshakeNonceSet, WAKE_BASE_NANOS, WAKE_JITTER_NANOS};
use shekyl_draw_rng::SplitMix64;
use shekyl_peerlist::ConnectorId;

/// A dial to our own listener: the listener reads the request while the
/// attempt is still in flight, and finds the nonce in the set.
#[test]
fn a_dial_to_our_own_listener_is_detected() {
    let mut rng = SplitMix64::new(1);
    let dialer = HandshakeNonceSet::new();
    let listener = dialer.clone();

    let attempt = dialer.mint(ConnectorId::Clearnet, &mut rng);
    let on_the_wire = *attempt.bytes();
    assert!(
        listener.take(ConnectorId::Clearnet, &on_the_wire),
        "our own request"
    );
    assert!(
        !listener.take(ConnectorId::Clearnet, &on_the_wire),
        "the query erases it: a replay of the request is not ours a second time"
    );
}

#[test]
fn a_nonce_is_recorded_before_it_is_handed_out_and_erased_on_every_end_path() {
    let mut rng = SplitMix64::new(2);
    let set = HandshakeNonceSet::new();
    assert_eq!(set.in_flight(ConnectorId::Tor), 0);
    {
        let attempt = set.mint(ConnectorId::Tor, &mut rng);
        assert_eq!(
            set.in_flight(ConnectorId::Tor),
            1,
            "in the set when mint returns"
        );
        assert_ne!(attempt.bytes(), &[0u8; 32]);
    }
    assert_eq!(
        set.in_flight(ConnectorId::Tor),
        0,
        "dropping the attempt erases it"
    );

    // An attempt that ends by panic still erases.
    let shared = set.clone();
    let result = std::thread::spawn(move || {
        let mut rng = SplitMix64::new(3);
        let _attempt = shared.mint(ConnectorId::Tor, &mut rng);
        panic!("the handshake task died");
    })
    .join();
    assert!(result.is_err());
    assert_eq!(set.in_flight(ConnectorId::Tor), 0);
}

#[test]
fn a_nonce_belongs_to_the_connector_it_was_minted_on() {
    let mut rng = SplitMix64::new(4);
    let set = HandshakeNonceSet::new();
    let attempt = set.mint(ConnectorId::Tor, &mut rng);
    let nonce = *attempt.bytes();
    assert!(
        !set.take(ConnectorId::Clearnet, &nonce),
        "an inbound clearnet session does not match a Tor attempt"
    );
    assert_eq!(set.in_flight(ConnectorId::Tor), 1, "and does not erase it");
    assert!(set.take(ConnectorId::Tor, &nonce));
}

#[test]
fn nonces_are_fresh_per_attempt_and_a_stranger_is_not_ours() {
    let mut rng = SplitMix64::new(5);
    let set = HandshakeNonceSet::new();
    let first = set.mint(ConnectorId::Clearnet, &mut rng);
    let second = set.mint(ConnectorId::Clearnet, &mut rng);
    assert_ne!(first.bytes(), second.bytes());
    assert_ne!(first.bytes(), &[0u8; 32]);
    assert!(!set.take(ConnectorId::Clearnet, &[0x5a; 32]));
    assert_eq!(set.in_flight(ConnectorId::Clearnet), 2);
}

#[test]
fn the_wake_gap_is_half_a_second_plus_up_to_one_second() {
    let mut rng = SplitMix64::new(6);
    let mut low = u64::MAX;
    let mut high = 0;
    let mut sum = 0u128;
    let draws = 20_000u64;
    for _ in 0..draws {
        let gap = next_wake_nanos(&mut rng);
        assert!((WAKE_BASE_NANOS..=WAKE_BASE_NANOS + WAKE_JITTER_NANOS).contains(&gap));
        low = low.min(gap);
        high = high.max(gap);
        sum += u128::from(gap);
    }
    let mean = u64::try_from(sum / u128::from(draws)).expect("fits");
    // Mean 1 s; both ends of the range are reached to within 1 %.
    assert!((990_000_000..=1_010_000_000).contains(&mean), "mean {mean}");
    assert!(low < WAKE_BASE_NANOS + WAKE_JITTER_NANOS / 100);
    assert!(high > WAKE_BASE_NANOS + WAKE_JITTER_NANOS * 99 / 100);
}
