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
    /// The daemon's state (`daemon_status`). The base fields are `health`'s:
    /// whether this node is usable now. Each part is shown whole to a caller
    /// its grant admits, and absent otherwise (RK-D23): the chain's facts to
    /// `chain`, the relayed pool's count to `pool` (`RPC_CHANNEL.md` §6.1).
    /// The Tor status is `INPUT_GRAMMAR.md` §23 as Part G amends it:
    /// `hiding` is `health`'s, and the rest is a part shown to `status`,
    /// in `shekyl-tor-status`'s types (`TOR_STATUS_CRATE.md`).
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
        /// An address-hiding session exists now: the relay's verdict, the
        /// class part, with no pin state (IG-Q67). Clients decide sends from
        /// `origination`, never from this.
        hiding: bool,
        writer: Writer,
        protocol_version: Integer,
        grant: Vec<GrantName>;
        part Policy::Grant(Grant::Chain) => {
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
        }
        part Policy::Grant(Grant::Pool) => {
            /// The entries this node has made public; `null` while the pool
            /// is retired.
            txpool_count: Nullable<Count>,
        }
        part Policy::Grant(Grant::Status) => {
            started: Time,
            disk_free: Size,
            data_size: Size,
            /// The RandomX caches the node's hasher holds now, 256 MiB
            /// each: the operator's memory fact, beside `data_size`
            /// (`RANDOMX_CACHE_ACTOR.md` §5.6). Every place in use is
            /// counted, whether its cache is warm, lent, being built or
            /// being dropped, so the count is never above three.
            randomx_caches: Count,
            revision: Text,
            /// `null` while P2P is off.
            peer_outbound_count: Nullable<Count>,
            /// `null` while P2P is off.
            peer_inbound_count: Nullable<Count>,
            alt_count: Count,
            rpc_connections: Count,
            txpool_retired: bool,
            /// The `tor` and `clearnet` settings (`TSR-Q12`).
            posture: shekyl_tor_status::Posture,
            /// What happens to this node's own transactions (IG-Q68).
            origination: shekyl_tor_status::Origination,
            /// The connectors the node syncs over now.
            sync_connector: Vec<shekyl_tor_status::Connector>,
            /// The quiet line, under every `tor` setting (IG-Q99).
            tor_quiet: Nullable<shekyl_tor_status::TorQuiet>,
            /// The managed supervisor's projection; `null` unless
            /// `posture.tor` is `managed`.
            tor: Nullable<shekyl_tor_status::ManagedTor>,
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

impl DaemonStatus {
    /// The Tor status the Status part carries, in `shekyl-tor-status`'s
    /// shape, for its one renderer and the send flow's one accessor.
    /// `None` for a caller not shown Status: the part is absent whole, so
    /// no Tor field stands in for it (RK-D23).
    #[must_use]
    pub fn tor_status(&self) -> Option<shekyl_tor_status::TorStatus> {
        Some(shekyl_tor_status::TorStatus {
            posture: self.posture.clone().shown()?,
            origination: self.origination.clone().shown()?,
            sync_connector: self.sync_connector.clone().shown()?,
            tor_quiet: self.tor_quiet.clone().shown()?.0,
            tor: self.tor.clone().shown()?.0,
        })
    }
}

/// A typed refusal (IG-11): a JSON-RPC error's `data` (RW-Q3), and a
/// reply's `cause` where a state is explained. One type: the registry's.
pub use crate::errors::Diagnostic;
