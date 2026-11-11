// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Peers, sync, P2P statistics and the relay's tallies.

use crate::kinds::{Count, Duration, Endpoint, Height, Rate, Size, Text, Time};
use crate::nullable::Nullable;

crate::wire_keywords! {
    /// A connector.
    pub enum Connector {
        Clearnet = "clearnet",
        Tor = "tor",
    }
}

crate::wire_keywords! {
    /// What chain sync's header run is doing with a session.
    pub enum SyncMode {
        Idle = "idle",
        Reachable = "reachable",
        Slot = "slot",
        Challenging = "challenging",
        PastCap = "past-cap",
        EvidenceCandidate = "evidence-candidate",
        Evidence = "evidence",
    }
}

crate::wire_keywords! {
    /// Chain sync's derived state (IG-Q80).
    pub enum SyncState {
        /// No session has completed a handshake.
        Unpeered = "unpeered",
        Behind = "behind",
        Following = "following",
        Synced = "synced",
    }
}

crate::wire_object! {
    /// A header read in flight to a session.
    ["sync session header"]
    pub struct HeaderRead {
        pub age: Duration,
        pub due: Duration,
    }
}

crate::wire_object! {
    /// A body span in flight to a session.
    ["sync session span"]
    pub struct BodySpan {
        pub from: Height,
        pub blocks: Count,
        /// The response its deadline is planned for.
        pub size: Size,
        pub age: Duration,
        pub due: Duration,
    }
}

crate::wire_object! {
    /// A peer session chain sync holds.
    ["sync session"]
    pub struct Session {
        /// The connection's id, as `peer_connections` gives it.
        pub connection: Text,
        pub endpoint: Endpoint,
        /// The tip the peer claims; `null` before it has claimed.
        pub height: Nullable<Height>,
        pub mode: SyncMode,
        pub header: Nullable<HeaderRead>,
        pub span: Vec<BodySpan>,
        /// What its last response arrived at; `null` until one has.
        pub download_speed: Nullable<Rate>,
    }
}

crate::wire_object! {
    /// Chain sync's view (`sync_status`).
    ["sync"]
    pub struct SyncStatus {
        pub height: Height,
        pub target_height: Height,
        pub state: SyncState,
        pub stalled: bool,
        pub session: Vec<Session>,
    }
}

crate::wire_object! {
    /// One live P2P connection.
    ["peer connection"]
    pub struct Connection {
        pub inbound: bool,
        pub local: bool,
        pub endpoint: Endpoint,
        pub connector: Connector,
        pub download: Size,
        pub upload: Size,
        pub download_idle: Duration,
        pub upload_idle: Duration,
        /// `null` for a connection chain sync does not hold.
        pub mode: Nullable<SyncMode>,
        pub age: Duration,
        pub download_speed_average: Rate,
        pub download_speed_current: Rate,
        pub upload_speed_average: Rate,
        pub upload_speed_current: Rate,
        pub id: Text,
        /// The tip the peer claims; `null` before it has claimed.
        pub height: Nullable<Height>,
    }
}

crate::wire_object! {
    /// `peer_list`'s input.
    ["peer"]
    pub struct PeerListQuery {
        /// Include endpoints not dialable on the public internet. Off by
        /// default.
        #[serde(default)]
        pub local [optional]: bool,
    }
}

crate::wire_keywords! {
    /// Which peer list holds an entry.
    pub enum Tier {
        White = "white",
        Gray = "gray",
    }
}

crate::wire_object! {
    /// One peer list entry.
    ["peer"]
    pub struct PeerEntry {
        pub endpoint: Endpoint,
        pub tier: Tier,
    }
}

crate::wire_object! {
    /// P2P statistics since the daemon started.
    ["p2p"]
    pub struct P2pStats {
        pub started: Time,
        pub download: Size,
        pub upload: Size,
        pub download_packets: Count,
        pub upload_packets: Count,
    }
}

crate::wire_object! {
    /// One connector's outbound floor.
    ["relay floor"]
    pub struct Floor {
        pub connector: Connector,
        pub outbound_count: Count,
        pub outbound_min: Count,
        pub below: bool,
    }
}

crate::wire_object! {
    /// One successor's stem counts.
    ["relay tally"]
    pub struct Tally {
        /// The connection's id, as `peer_connections` gives it (IG-Q83).
        pub connection: Text,
        /// `null` where the connector has not been observed.
        pub connector: Nullable<Connector>,
        pub propagated: Count,
        pub silent: Count,
        pub sender_count: Count,
    }
}

crate::wire_object! {
    /// The relay's floor and stem tallies (host-only, RT-O9.3).
    ["relay"]
    pub struct RelayStats {
        pub floor: Vec<Floor>,
        pub tally: Vec<Tally>,
    }
}
