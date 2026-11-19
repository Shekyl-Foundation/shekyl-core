// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cover classification: which sessions carry it, and what a carrier
//! refuses (`CVR-R2`, `CVR-R3`).

use super::*;
use shekyl_draw_rng::SplitMix64;
use shekyl_relay_privacy::params::{inherited, DandelionParams};

/// A carrier is refused only for its shape, never for the connectors it
/// is built over (`CVR-R3`): a Tor-only node, a mixed node and a node with
/// no connector yet all build, and their channels carry cover wherever a
/// covered session holds the slot. The refusal that read a connector
/// (`NoiseWithoutOpenLink`) is deleted with the class it read.
///
/// Red edit: reinstate a connector check in `Relay::new`; the Tor-only and
/// empty builds fail.
#[test]
fn a_noise_carrier_is_refused_only_for_its_shape() {
    let build = |configured: &[ConnectorId], stems: usize, noise: bool| {
        let mut rng = SplitMix64::new(0x0819);
        Relay::new(
            DandelionParams::inherited(),
            stems,
            noise,
            configured,
            &[],
            0,
            &mut rng,
        )
    };
    const CHANNELS: usize = inherited::NOISE_CHANNELS;

    for configured in [
        &[ConnectorId::Clearnet][..],
        &[ConnectorId::Tor][..],
        &[ConnectorId::Clearnet, ConnectorId::Tor][..],
        &[][..],
    ] {
        assert!(
            build(configured, CHANNELS, true).is_ok(),
            "{configured:?}: a carrier builds over any connectors"
        );
    }
    assert_eq!(
        build(&[ConnectorId::Clearnet], CHANNELS + 1, true).err(),
        Some(RelayNewError::NoiseChannelCount { got: CHANNELS + 1 }),
        "a channel count the schedule is not sized for is refused"
    );
    assert_eq!(
        build(&[ConnectorId::Tor], CHANNELS + 1, true).err(),
        Some(RelayNewError::NoiseChannelCount { got: CHANNELS + 1 }),
        "the channel count is read whatever the connectors"
    );
    // The epoch's length is not a refusal: the tail after each boundary,
    // not the epoch, keeps a run on its own peer (`CVR-R4`).
    let mut short = DandelionParams::inherited();
    short.min_epoch_secs = 1;
    let mut rng = SplitMix64::new(0x0820);
    assert!(
        Relay::new(
            short,
            CHANNELS,
            true,
            &[ConnectorId::Clearnet],
            &[ConnectorId::Clearnet],
            0,
            &mut rng,
        )
        .is_ok(),
        "a carrier over a one-second epoch builds"
    );
}

#[test]
fn link_encryption_is_the_classical_cell_not_the_anonymity_cell() {
    assert!(link_encrypted(ConnectorId::Tor));
    assert!(!link_encrypted(ConnectorId::Clearnet));
    assert!(address_hidden_from_peer(ConnectorId::Tor));
    assert!(!address_hidden_from_peer(ConnectorId::Clearnet));
}

/// A session is encrypted by its connector's native cell or by a layer
/// this node adds to it, and nothing else: clearnet is plaintext unless
/// this node wraps it in Noise; Tor is encrypted whatever is added.
///
/// Red edits: drop `added_encryption` from `Relay::session_encrypted`
/// (clearnet under Noise reads plaintext), or read only it (Tor reads
/// plaintext).
#[test]
fn a_session_is_encrypted_natively_or_by_a_layer_this_node_adds() {
    let build = |added: &[ConnectorId]| {
        let mut rng = SplitMix64::new(0x0821);
        Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            added,
            0,
            &mut rng,
        )
        .expect("the zone builds")
    };
    let plain = build(&[]);
    assert!(plain.session_encrypted(ConnectorId::Tor));
    assert!(!plain.session_encrypted(ConnectorId::Clearnet));
    let layered = build(&[ConnectorId::Clearnet]);
    assert!(layered.session_encrypted(ConnectorId::Tor));
    assert!(layered.session_encrypted(ConnectorId::Clearnet));
}

/// Cover runs on a session that is encrypted and whose connector declares
/// its timing visible to an observer at this node's end, with no other
/// condition (`CVR-R3`; Rick, 2026-11-15):
///
/// - a Tor session carries cover, because Tor encrypts and its timing is
///   still seen as Tor traffic (the `CoverClass::Volume` refusal is gone);
/// - a plaintext clearnet session does not;
/// - a clearnet session this node wraps in Noise does;
/// - a column that has not assessed its local visibility does not, even on
///   an encrypted connector, because it does not declare its timing visible.
///
/// Red edits: drop the encryption term from `noise_destination` (plaintext
/// clearnet gets cover), or the visibility term (the unassessed column gets
/// cover), or reinstate a Tor refusal (the Tor session gets none).
#[test]
fn cover_runs_on_an_encrypted_session_whose_timing_is_visible() {
    let peer = |byte: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = byte;
        ConnectionId::from_bytes(bytes)
    };
    let zone = |added: &[ConnectorId]| {
        let mut rng = SplitMix64::new(0x0822);
        let mut zone = Relay::new(
            DandelionParams::inherited(),
            2,
            true,
            &[ConnectorId::Clearnet, ConnectorId::Tor],
            added,
            0,
            &mut rng,
        )
        .expect("the zone builds");
        zone.on_session_established(peer(1), PeerDirection::Outbound, ConnectorId::Tor, &mut rng);
        zone.on_session_established(
            peer(2),
            PeerDirection::Outbound,
            ConnectorId::Clearnet,
            &mut rng,
        );
        zone.admit_synthetic(
            peer(3),
            PeerDirection::Outbound,
            ConnectorId::Tor,
            Declaration::synthetic(Assessment::Assessed(YesNo::Yes), Assessment::NotAssessed),
        );
        zone
    };

    let plain = zone(&[]);
    assert!(
        plain.noise_destination(peer(1)),
        "a Tor session carries cover"
    );
    assert!(
        !plain.noise_destination(peer(2)),
        "a plaintext clearnet session carries none"
    );
    assert!(
        !plain.noise_destination(peer(3)),
        "an unassessed visibility cell is not timing visible"
    );
    assert!(
        !plain.noise_destination(peer(9)),
        "a gone session is not a destination"
    );

    let layered = zone(&[ConnectorId::Clearnet]);
    assert!(layered.noise_destination(peer(1)));
    assert!(
        layered.noise_destination(peer(2)),
        "a clearnet session under Noise carries cover"
    );
    assert!(!layered.noise_destination(peer(3)));
}
