// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain-sync heuristics that read the outbound target, decided in Rust
//! (`DAEMON_CONFIG_CUTOVER.md` §4.2, the reverse pulls). The dialer owns
//! each connector's outbound target; the C++ protocol handler used to pull
//! the number and compare it itself. Now it hands its counts over and
//! takes the verdict, so no C++ holds a copy of a Rust-owned value.

use crate::dialer_ffi::{default_target, dialer};
use shekyl_seam::connector_from_index;

/// The connector's outbound target: the dialer's, or the compiled default
/// before the dialer exists. 0 for an unknown connector.
fn target(connector: u32) -> u32 {
    let Some(connector) = connector_from_index(connector) else {
        return 0;
    };
    match dialer() {
        Some(dialer) => u32::try_from(dialer.target(connector)).unwrap_or(u32::MAX),
        None => default_target(connector),
    }
}

/// How many peers a node keeps searching for a sync source among before it
/// stops dropping synced peers to make room: the C++
/// `P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT`.
const SYNC_SEARCH_CONNECTIONS: u32 = 2;

/// Whether the protocol handler should drop a synced peer on `connector`
/// to make room for a syncing one: the outbound slots are full
/// (`synced + syncing` reaches the target) and fewer than the search count
/// are syncing. The caller still needs a synced peer to drop.
#[no_mangle]
pub extern "C" fn shekyl_sync_room_for_syncing_peer(
    connector: u32,
    syncing: u32,
    synced: u32,
) -> bool {
    let target = target(connector);
    synced.saturating_add(syncing) >= target && syncing < SYNC_SEARCH_CONNECTIONS
}

/// Whether the protocol handler should look for more outbound peers to
/// sync from on `connector`: fewer than the target are connected.
#[no_mangle]
pub extern "C" fn shekyl_sync_wants_more_outbound(connector: u32, outbound: u32) -> bool {
    outbound < target(connector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rules_read_the_default_target_before_a_dialer_exists() {
        let clearnet = u32::try_from(crate::dialer_ffi::ConnectorId::Clearnet.index()).unwrap();
        let t = target(clearnet);
        assert!(t > 0);
        assert!(shekyl_sync_wants_more_outbound(clearnet, t - 1));
        assert!(!shekyl_sync_wants_more_outbound(clearnet, t));
        assert!(shekyl_sync_room_for_syncing_peer(clearnet, 1, t - 1));
        assert!(!shekyl_sync_room_for_syncing_peer(clearnet, 1, t - 2));
        assert!(!shekyl_sync_room_for_syncing_peer(
            clearnet,
            SYNC_SEARCH_CONNECTIONS,
            t
        ));
        // An unknown connector has no target: nothing wanted, no room.
        assert!(!shekyl_sync_wants_more_outbound(99, 0));
    }
}
