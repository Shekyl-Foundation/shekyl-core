// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cover posture for one connector.
//!
//! Cover is a relay ruling on the declaration's threat cells. It is not
//! another cell: Tor hides the address and is classically encrypted, and
//! the ruling still sends no envelope there (`TOR_COVER_POSTURE.md`).

use shekyl_relay_privacy::verify_cost::{
    ADOPTED_TRANSIT_ASSUMPTION_MS, ANON_ZONE_TRANSIT_ASSUMPTION_MS,
};
use shekyl_transport_layer::ConnectorId;

/// What hides a stem on this connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverClass {
    /// An envelope is the only cover a wire observer cannot already see
    /// through. Substitution cover may run when the carrier was requested.
    OpenLink,
    /// The connector's own traffic is the cover. No envelope.
    Volume,
}

/// The ruling for `connector`.
///
/// Exhaustive: a new connector does not compile until it is classified.
/// Do not derive this from [`super::link_encrypted`] or from
/// [`super::address_hidden_from_peer`]. Those cells agree with this on
/// neither connector that exists today, and a later connector may set
/// only one of them.
#[must_use]
pub const fn cover_class(connector: ConnectorId) -> CoverClass {
    match connector {
        ConnectorId::Clearnet => CoverClass::OpenLink,
        ConnectorId::Tor => CoverClass::Volume,
    }
}

/// True when any configured connector can carry a substitution envelope.
#[must_use]
pub fn any_open_link(configured: &[ConnectorId]) -> bool {
    configured
        .iter()
        .copied()
        .any(|connector| matches!(cover_class(connector), CoverClass::OpenLink))
}

/// Measured transit for `connector`, in milliseconds.
///
/// `None` is a connector this relay does not stem on. The numbers are the
/// privacy crate's named assumptions. This match is the only place a
/// [`ConnectorId`] selects one: the flood instrument's row names are not
/// an index into this enum.
#[must_use]
pub const fn measured_transit_ms(connector: ConnectorId) -> Option<f64> {
    match connector {
        ConnectorId::Clearnet => Some(ADOPTED_TRANSIT_ASSUMPTION_MS),
        ConnectorId::Tor => Some(ANON_ZONE_TRANSIT_ASSUMPTION_MS),
    }
}

/// Open links in [`ConnectorId::ALL`].
///
/// The substitution-cover bandwidth ceiling counts these. Encrypted zones
/// do not: Tor is volume cover.
pub const OPEN_LINK_COUNT: u32 = {
    let mut open_links = 0u32;
    let mut index = 0;
    while index < ConnectorId::ALL.len() {
        if matches!(cover_class(ConnectorId::ALL[index]), CoverClass::OpenLink) {
            open_links += 1;
        }
        index += 1;
    }
    open_links
};

const _: () = {
    assert!(OPEN_LINK_COUNT == shekyl_relay_privacy::params::carrier::CEILING_ZONES);
};
