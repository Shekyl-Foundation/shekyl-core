// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cover and transit, read from the connector's declaration.
//!
//! Neither cell is chosen by naming a connector. An unassessed transit
//! is a connector this relay does not stem on. An assessed transit carries
//! its basis; today both built columns are assumptions
//! (`DAEMON_RELAY_PRIVACY.md` §97).
//!
//! **Cover reads two facts, both already on the wire's side of the table**
//! (`CVR-R2`, `CVR-R3`; Rick, 2026-11-15): whether the session is encrypted
//! ([`super::Relay`]'s reading, the connector's native cell or a layer this
//! node added) and whether the connector declares that an observer at this
//! node's end sees the connection's timing ([`timing_visible`]). There is no
//! third cell. A `CoverClass` cell stored the 2026-09-04 ruling that Tor's
//! own volume was its cover as if it were a fact about the connector; TRC-1
//! measured that it is not (`TOR_COVER_POSTURE.md`, banner of 2026-11-15),
//! and the cell was deleted rather than re-valued (rules 21 and 23).

use shekyl_relay_privacy::basis::DerivationMs;
use shekyl_transport_layer::{declaration, Assessment, ConnectorId, Declaration, LocalVisibility};

/// Whether an observer at this node's end sees when this connector's
/// connection carries bytes, read from the declaration's
/// `local_observer_visibility` cell.
///
/// Both assessed values say so: [`LocalVisibility::Visible`] and
/// [`LocalVisibility::VisibleAsTor`] each name the connection's timing,
/// volume and sizes; the second only says the bytes are seen as Tor
/// traffic. [`Assessment::NotAssessed`] is not presumed visible, so such a
/// column gets no cover.
#[must_use]
pub const fn timing_visible(declaration: &Declaration) -> bool {
    matches!(
        declaration.local_observer_visibility(),
        Assessment::Assessed(LocalVisibility::Visible | LocalVisibility::VisibleAsTor)
    )
}

/// The declared transit for `connector`, with its basis.
///
/// [`None`] is a connector this relay does not stem on.
/// *Records-was: `measured_transit_ms`, returning a bare `f64`.*
#[must_use]
pub const fn transit_ms(connector: ConnectorId) -> Option<DerivationMs> {
    match declaration(connector.column()).transit_ms() {
        Assessment::Assessed(transit) => Some(transit),
        Assessment::NotAssessed => None,
    }
}
