// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hidden class's operator report (`hidden_slot`): reported on a change
//! of state between none, one and several address-hiding sessions, never
//! once per epoch, and first at the first epoch rebuild.

use super::hidden_slot::{hidden_class_report, HiddenClass};
use super::*;

use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::params::DandelionParams;

const CLASSES: [HiddenClass; 3] = [HiddenClass::Empty, HiddenClass::One, HiddenClass::Several];

fn id(byte: u8) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    ConnectionId::from_bytes(bytes)
}

fn relay(configured: &[ConnectorId], rng: &mut SplitMix64) -> Relay {
    Relay::new(DandelionParams::inherited(), 2, false, configured, 0, rng)
        .expect("width two is legal with a hidden connector and noise off")
}

fn outbound(relay: &mut Relay, byte: u8, connector: ConnectorId, rng: &mut SplitMix64) {
    relay.on_session_established(id(byte), PeerDirection::Outbound, connector, rng);
}

#[test]
fn a_report_is_made_on_a_change_of_state_and_first_at_a_rebuild() {
    for observed in CLASSES {
        assert_eq!(
            hidden_class_report(None, observed, false),
            None,
            "nothing is reported before the first rebuild: {observed:?}"
        );
        assert_eq!(
            hidden_class_report(None, observed, true),
            Some(observed),
            "the first rebuild reports the state it finds: {observed:?}"
        );
        for previous in CLASSES {
            for at_rebuild in [false, true] {
                let expected = (previous != observed).then_some(observed);
                assert_eq!(
                    hidden_class_report(Some(previous), observed, at_rebuild),
                    expected,
                    "{previous:?} -> {observed:?} (rebuild {at_rebuild})"
                );
            }
        }
    }
}

/// A node with Tor configured and only clearnet peers (the default posture
/// with no onion peer to dial) reports the empty class at the first rebuild,
/// then follows each change of state as sessions open and close, and stays
/// put across rebuilds that find the same state.
#[test]
fn the_reported_class_follows_the_session_set() {
    let mut rng = SplitMix64::new(7);
    let mut z = relay(&[ConnectorId::Clearnet, ConnectorId::Tor], &mut rng);
    outbound(&mut z, 10, ConnectorId::Clearnet, &mut rng);
    outbound(&mut z, 11, ConnectorId::Clearnet, &mut rng);
    assert_eq!(
        z.reported_hidden_class(),
        None,
        "no report before the first rebuild"
    );

    z.rebuild_stems(&mut rng);
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Empty));
    z.rebuild_stems(&mut rng);
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Empty));

    outbound(&mut z, 1, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.reported_hidden_class(),
        Some(HiddenClass::One),
        "the first address-hiding session is reported when it opens, not at the next rebuild"
    );
    for _ in 0..3 {
        z.rebuild_stems(&mut rng);
        assert_eq!(z.reported_hidden_class(), Some(HiddenClass::One));
    }

    outbound(&mut z, 2, ConnectorId::Tor, &mut rng);
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Several));
    outbound(&mut z, 3, ConnectorId::Tor, &mut rng);
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Several));

    z.on_connection_close(&id(3));
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Several));
    z.on_connection_close(&id(2));
    assert_eq!(
        z.reported_hidden_class(),
        Some(HiddenClass::One),
        "a close that leaves one address-hiding session is reported at the close"
    );
    z.on_connection_close(&id(1));
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Empty));

    z.on_session_established(id(4), PeerDirection::Inbound, ConnectorId::Tor, &mut rng);
    assert_eq!(
        z.reported_hidden_class(),
        Some(HiddenClass::Empty),
        "an inbound session does not hide this node's address from anyone it sends to"
    );
}

/// A node that starts with several address-hiding sessions has nothing to
/// report: the first rebuild records the healthy state silently.
#[test]
fn a_healthy_start_records_several_at_the_first_rebuild() {
    let mut rng = SplitMix64::new(9);
    let mut z = relay(&[ConnectorId::Clearnet, ConnectorId::Tor], &mut rng);
    for byte in 1..=3 {
        outbound(&mut z, byte, ConnectorId::Tor, &mut rng);
    }
    assert_eq!(z.reported_hidden_class(), None);
    z.rebuild_stems(&mut rng);
    assert_eq!(z.reported_hidden_class(), Some(HiddenClass::Several));
}

/// With no configured connector that hides the address the map is uniform:
/// there is no hidden class and nothing is reported.
#[test]
fn a_uniform_map_has_no_hidden_class() {
    let mut rng = SplitMix64::new(5);
    let mut z = relay(&[ConnectorId::Clearnet], &mut rng);
    outbound(&mut z, 10, ConnectorId::Clearnet, &mut rng);
    z.rebuild_stems(&mut rng);
    z.on_connection_close(&id(10));
    z.rebuild_stems(&mut rng);
    assert_eq!(z.reported_hidden_class(), None);
}
