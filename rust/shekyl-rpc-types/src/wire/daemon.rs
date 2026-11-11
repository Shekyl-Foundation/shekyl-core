// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's own state (`daemon_status`), and the diagnostic every
//! refusal carries.

use super::chain::Writer;
use crate::hash::HashHex;
use crate::hex128::HexU128;
use crate::kinds::{Count, Duration, Height, Integer, Micro, Size, Text, Time};
use crate::method::Policy;
use crate::nullable::Nullable;
use crate::schema::{Schema, Shape};
use shekyl_rpc_grants::Grant;
use shekyl_units::wire::AtomicUnitsString as Amount;

crate::wire_object! {
    /// One connector's counts (IG-Q82).
    ["connector"]
    pub struct ConnectorCounts {
        pub inbound_count: Count,
        pub outbound_count: Count,
        pub peer_white_count: Count,
        pub peer_gray_count: Count,
    }
}

/// Each connector the node runs, and its counts. A connector it does not
/// run has no key (IG-Q82).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorMap {
    /// The clearnet connector's counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearnet: Option<ConnectorCounts>,
    /// The Tor connector's counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tor: Option<ConnectorCounts>,
}

impl Schema for ConnectorMap {
    fn shape() -> Shape {
        Shape::Map {
            keys: Some(&["clearnet", "tor"]),
            value: Box::new(ConnectorCounts::shape()),
        }
    }
}

crate::wire_keywords! {
    /// A grant a connection may hold (`RPC_CHANNEL.md` §6.1).
    pub enum GrantName {
        Health = "health",
        Status = "status",
        Chain = "chain",
        Pool = "pool",
        Peers = "peers",
        Submit = "submit",
        MiningWork = "mining-work",
        MiningControl = "mining-control",
        Bans = "bans",
        Node = "node",
        Config = "config",
        Enrol = "enrol",
    }
}

impl From<Grant> for GrantName {
    fn from(grant: Grant) -> Self {
        match grant {
            Grant::Health => Self::Health,
            Grant::Status => Self::Status,
            Grant::Chain => Self::Chain,
            Grant::Pool => Self::Pool,
            Grant::Peers => Self::Peers,
            Grant::Submit => Self::Submit,
            Grant::MiningWork => Self::MiningWork,
            Grant::MiningControl => Self::MiningControl,
            Grant::Bans => Self::Bans,
            Grant::Node => Self::Node,
            Grant::Config => Self::Config,
            Grant::Enrol => Self::Enrol,
        }
    }
}

crate::wire_parted! {
    /// The daemon's state (`daemon_status`). Each part is shown whole to a
    /// caller its grant admits, and absent otherwise (RK-D23). Part E's and
    /// Part G's Tor fields join when the Tor lane's status PRs land.
    ["daemon"]
    pub struct DaemonStatus {
        height: Height,
        hash: HashHex,
        target_height: Nullable<Height>,
        synchronized: bool,
        syncing: bool,
        offline: bool,
        degraded: bool,
        /// `null` while P2P is off.
        peered: Nullable<bool>,
        writer: Writer,
        protocol_version: Integer,
        difficulty: HexU128,
        difficulty_cumulative: HexU128,
        block_spacing: Duration,
        tx_count: Count,
        block_weight_max: Size,
        block_weight_median: Size,
        time_adjusted: Time,
        emission: Amount,
        emission_multiplier: Micro,
        burn: Micro,
        burn_total: Amount,
        stake_share: Micro,
        /// `null` while the pool is retired.
        txpool_count: Nullable<Count>,
        grant: Vec<GrantName>;
        part Policy::Grant(Grant::Status) => {
            started: Time,
            disk_free: Size,
            data_size: Size,
            revision: Text,
            /// `null` while P2P is off.
            peer_outbound_count: Nullable<Count>,
            /// `null` while P2P is off.
            peer_inbound_count: Nullable<Count>,
            alt_count: Count,
            rpc_connections: Count,
            txpool_retired: bool,
        }
        part Policy::Grant(Grant::Peers) => {
            connector: ConnectorMap,
        }
        part Policy::HostOnly => {
            /// `null` while the pool is retired.
            txpool_private_count: Nullable<Count>,
        }
    }
}

/// A typed refusal (IG-11): a JSON-RPC error's `data` (RW-Q3), and a
/// reply's `cause` where a state is explained. One type: the registry's.
pub use crate::errors::Diagnostic;
