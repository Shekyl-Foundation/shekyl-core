// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the relay task publishes for readers on other threads: the RPC's
//! `relay_stats` and the node's health. One value, replaced whole
//! after each change; a reader takes the `Arc` and reads a consistent
//! copy. Nothing here is written by a reader (§18.5).

use crate::floor_diag::FloorSnapshot;
use crate::graph::ConnectorId;
use crate::stem_watch::StemTallySnapshot;
use shekyl_relay_privacy::stem_map::ConnectionId;

/// The relay zone's published reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelaySnapshot {
    /// Whether the zone runs the covert carrier.
    pub noise: bool,
    /// Stem slots backed by a live peer.
    pub live_stems: usize,
    /// Stem observations whose embargo has not resolved.
    pub stem_in_flight: usize,
    /// Per successor: how its stems resolved (`DAEMON_RELAY_PRIVACY.md`
    /// §35), in the zone's order.
    pub tallies: Vec<(ConnectionId, StemTallySnapshot)>,
    /// Per configured connector: achieved outbound connections against
    /// the provisioning floor (§16.6), once observed.
    pub floors: Vec<(ConnectorId, FloorSnapshot)>,
}
