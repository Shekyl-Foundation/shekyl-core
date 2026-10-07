// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cover and measured transit, read from the connector's declaration.
//!
//! Neither cell is chosen by naming a connector. An unassessed transit
//! is a connector this relay does not stem on.

use shekyl_transport_layer::{declaration, Assessment, ConnectorId, CoverClass};

/// The ruling recorded on `connector`'s declaration.
///
/// [`None`] is a cell nobody has assessed. It is not an open link and
/// not volume cover.
#[must_use]
pub const fn cover_class(connector: ConnectorId) -> Option<CoverClass> {
    match declaration(connector.column()).cover_class() {
        Assessment::Assessed(class) => Some(class),
        Assessment::NotAssessed => None,
    }
}

/// True when any configured connector can carry a substitution envelope.
#[must_use]
pub fn any_open_link(configured: &[ConnectorId]) -> bool {
    configured
        .iter()
        .copied()
        .any(|connector| matches!(cover_class(connector), Some(CoverClass::OpenLink)))
}

/// Measured transit for `connector`, in milliseconds.
///
/// [`None`] is a connector this relay does not stem on.
#[must_use]
pub fn measured_transit_ms(connector: ConnectorId) -> Option<f64> {
    match declaration(connector.column()).measured_transit_ms() {
        Assessment::Assessed(ms) => Some(f64::from(ms)),
        Assessment::NotAssessed => None,
    }
}

/// Open links in [`ConnectorId::ALL`].
///
/// The substitution-cover bandwidth ceiling counts these.
pub const OPEN_LINK_COUNT: u32 = {
    let mut open_links = 0u32;
    let mut index = 0;
    while index < ConnectorId::ALL.len() {
        if matches!(
            cover_class(ConnectorId::ALL[index]),
            Some(CoverClass::OpenLink)
        ) {
            open_links += 1;
        }
        index += 1;
    }
    open_links
};

const _: () = {
    assert!(OPEN_LINK_COUNT == shekyl_relay_privacy::params::carrier::CEILING_ZONES);
};
