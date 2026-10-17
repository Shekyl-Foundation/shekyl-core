// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The hidden class's operator report (`hidden_slot`): the watch arms at
//! the first epoch rebuild, and after that reports a change of state
//! between empty, one and several address-hiding sessions. The notice names
//! the class. It does not say an exhausted origin pin has resumed.

use super::hidden_slot::{
    DegradedHiddenClass, HiddenClass, HiddenClassLevel, HiddenClassLine, HiddenClassNotice,
    HiddenClassWatch,
};
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

/// The census a class stands for in the transition table. Several is more
/// than one, and the notice carries this count rather than a fixed stand-in.
fn sessions_for(class: HiddenClass) -> usize {
    match class {
        HiddenClass::Empty => 0,
        HiddenClass::One => 1,
        HiddenClass::Several => 4,
    }
}

/// The report the watch owes for this transition. `arm` is the epoch rebuild.
///
/// Before the first rebuild nothing is recorded. The first several is quiet.
/// Every other entrance is a warning, and a later several carries the census.
fn expected_notice(
    previous: Option<HiddenClass>,
    observed: HiddenClass,
    arm: bool,
) -> Option<HiddenClassNotice> {
    let entered = match previous {
        None => arm,
        Some(class) => class != observed,
    };
    if !entered {
        return None;
    }
    let sessions = sessions_for(observed);
    Some(match (previous, observed) {
        (None, HiddenClass::Several) => HiddenClassNotice::Quiet,
        (_, HiddenClass::Several) => HiddenClassNotice::Recovered { sessions },
        (_, HiddenClass::Empty) => HiddenClassNotice::Warn(DegradedHiddenClass::Empty),
        (_, HiddenClass::One) => HiddenClassNotice::Warn(DegradedHiddenClass::One),
    })
}

fn stored_after(
    previous: Option<HiddenClass>,
    observed: HiddenClass,
    arm: bool,
) -> HiddenClassWatch {
    if previous.is_none() && !arm {
        HiddenClassWatch::BeforeRebuild
    } else {
        HiddenClassWatch::Reported(observed)
    }
}

#[test]
fn the_watch_arms_at_the_first_rebuild_and_then_reports_a_change() {
    for observed in CLASSES {
        for previous in [
            None,
            Some(HiddenClass::Empty),
            Some(HiddenClass::One),
            Some(HiddenClass::Several),
        ] {
            for arm in [false, true] {
                let mut watch = match previous {
                    None => HiddenClassWatch::BeforeRebuild,
                    Some(class) => HiddenClassWatch::Reported(class),
                };
                let notice = if arm {
                    watch.arm(sessions_for(observed))
                } else {
                    watch.note(sessions_for(observed))
                };
                assert_eq!(
                    notice,
                    expected_notice(previous, observed, arm),
                    "{previous:?} -> {observed:?} (rebuild {arm})"
                );
                assert_eq!(
                    watch,
                    stored_after(previous, observed, arm),
                    "stored class after {previous:?} -> {observed:?} (rebuild {arm})"
                );
            }
        }
    }
}

/// `Recovered` carries the census, not the table's stand-in of four.
#[test]
fn a_recovery_names_the_session_count() {
    let mut watch = HiddenClassWatch::Reported(HiddenClass::One);
    assert_eq!(
        watch.note(7),
        Some(HiddenClassNotice::Recovered { sessions: 7 })
    );
    assert_eq!(watch, HiddenClassWatch::Reported(HiddenClass::Several));
    assert_eq!(watch.note(2), None, "several stays several");
    assert_eq!(
        watch.arm(2),
        None,
        "a rebuild that finds several says nothing"
    );
}

/// The lines name the class. An exhausted origin pin stays `NoOwnEdge`
/// until the epoch ends (§98.5); these lines do not say it has resumed.
#[test]
fn a_notice_names_the_class_and_not_the_origin_pin() {
    assert_eq!(HiddenClassNotice::Quiet.line(), None);
    assert_eq!(
        HiddenClassNotice::Warn(DegradedHiddenClass::Empty).line(),
        Some(HiddenClassLine {
            level: HiddenClassLevel::Warn,
            text: "no outbound connection hides this node's address, so a transaction this node originates has no address-hiding session to leave on".to_string(),
        })
    );
    assert_eq!(
        HiddenClassNotice::Warn(DegradedHiddenClass::One).line(),
        Some(HiddenClassLine {
            level: HiddenClassLevel::Warn,
            text: "hop-0 edge cannot rotate: one outbound connection hides this node's address"
                .to_string(),
        })
    );
    assert_eq!(
        HiddenClassNotice::Recovered { sessions: 3 }.line(),
        Some(HiddenClassLine {
            level: HiddenClassLevel::Info,
            text: "3 outbound connections hide this node's address".to_string(),
        })
    );
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
