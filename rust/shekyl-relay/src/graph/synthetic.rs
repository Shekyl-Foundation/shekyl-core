// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A declaration that is not Clearnet and not Tor.
//!
//! The production path copies a connector's column onto the session. This
//! module admits a column the table does not have, labelled as clearnet, and
//! the draws follow the column.

use super::*;

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::rng::SplitMix64;
use shekyl_relay_privacy::verify_cost::{
    ADOPTED_TRANSIT_ASSUMPTION_MS, ANON_ZONE_TRANSIT_ASSUMPTION_MS,
};
use shekyl_transport_layer::YesNo;

const SYNTHETIC_TRANSIT_MS: u32 = 900;

fn id(byte: u8) -> ConnectionId {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    ConnectionId::from_bytes(bytes)
}

fn hidden_column(transit: Assessment<u32>) -> Declaration {
    Declaration::synthetic(
        Assessment::Assessed(YesNo::Yes),
        transit,
        Assessment::Assessed(CoverClass::Volume),
    )
}

fn relay(rng: &mut SplitMix64) -> Relay {
    Relay::new(
        DandelionParams::inherited(),
        2,
        false,
        &[ConnectorId::Tor],
        0,
        rng,
    )
    .unwrap()
}

#[test]
fn the_built_columns_keep_the_measured_transits() {
    assert_eq!(
        measured_transit_ms(ConnectorId::Clearnet),
        Some(ADOPTED_TRANSIT_ASSUMPTION_MS)
    );
    assert_eq!(
        measured_transit_ms(ConnectorId::Tor),
        Some(ANON_ZONE_TRANSIT_ASSUMPTION_MS)
    );
}

#[test]
fn a_synthetic_column_drives_stem_own_edge_and_embargo() {
    let mut rng = SplitMix64::new(9);
    let mut relay = relay(&mut rng);
    let measured = hidden_column(Assessment::Assessed(SYNTHETIC_TRANSIT_MS));
    let unmeasured = hidden_column(Assessment::NotAssessed);
    // Labelled clearnet. Clearnet does not hide the address and its transit
    // is 50 ms. The column says otherwise.
    relay.admit_synthetic(
        id(1),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        measured,
    );
    relay.admit_synthetic(
        id(2),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        unmeasured,
    );
    relay.on_session_established(
        id(3),
        PeerDirection::Outbound,
        ConnectorId::Clearnet,
        &mut rng,
    );

    relay.update_stems(&mut rng);
    assert_eq!(
        relay.live_stems(),
        2,
        "the unmeasured column is not a stem candidate; clearnet and the synthetic column are"
    );

    let plan = relay.plan_relay(None, true, NodeSync::Synchronised, &mut rng);
    assert_eq!(
        plan,
        RelayPlan::OwnEdge(id(1)),
        "the own-edge pool is the column that hides the address, not the clearnet label"
    );

    let tx = TxId::from_bytes([9u8; 32]);
    relay.record_stem(&[tx], id(2), None, 0, &mut rng);
    assert_eq!(
        relay.stem_connector(tx),
        None,
        "unassessed transit records nothing"
    );
    relay.record_stem(&[tx], id(1), None, 0, &mut rng);
    assert_eq!(relay.stem_connector(tx), Some(ConnectorId::Clearnet));

    let synthetic_mean = embargo_timer(&measured).map(|timer| timer.mean_secs());
    assert!(synthetic_mean.is_some());
    assert_ne!(
        synthetic_mean,
        relay.embargo_mean_secs(ConnectorId::Clearnet)
    );
    assert_ne!(synthetic_mean, relay.embargo_mean_secs(ConnectorId::Tor));
}
