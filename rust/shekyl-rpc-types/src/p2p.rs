// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The p2p-facing read methods — the RK-5a slice of the daemon RPC KV
//! cutover (`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.1).
//!
//! Single Rust definitions of the wire types `COMMAND_RPC_SYNC_INFO`,
//! `COMMAND_RPC_GET_NET_STATS`, `COMMAND_RPC_GET_PEER_LIST` and
//! `COMMAND_RPC_GET_CONNECTIONS` used to carry in C++. Conventions are
//! [`crate::chain`]'s: wire field names, `deny_unknown_fields`, and every
//! `KV_SERIALIZE_OPT(field, default)` mirrored by `#[serde(default,
//! skip_serializing_if = …)]` so a reply is byte-equal to the captured epee
//! document.
//!
//! Three shape facts these methods have that the earlier slices did not, each
//! pinned by a vector in `tests/vectors/rpc/`:
//!
//! - **Every empty sequence is omitted, not `[]`.** An idle daemon answers
//!   `/get_peer_list` with `{"status":"OK"}` and nothing else — measured on a
//!   live regtest node before the types were written, and captured as
//!   `get_peer_list_empty_v1.json`.
//! - **`public_only` defaults to `true`.** It is the one `OPT` default in
//!   this slice that is not `false`, so it is omitted when true and emitted
//!   when false — the inverse of every other optional field here.
//! - **`ip` is two different types under one name.** [`Peer::ip`] is a
//!   number (an ipv4 address with its octets in network order, zero for every
//!   other address arm);
//!   [`ConnectionInfo::ip`] is a string. Modelling both as one shape
//!   round-trips neither.
//!
//! One member of the C++ `connection_info` is **not** here:
//! `ssl` had no `KV_SERIALIZE` row, so it never reached the wire. It is not
//! reintroduced — p2p SSL is structurally disabled (the p2p listener is
//! initialized `e_ssl_support_disabled` and the outbound support flag's only
//! assignment is the same value), so the field could only ever have carried
//! `false`. See the design doc's §5 register.

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;

/// Response of `GET|POST /get_net_stats`. The request body is empty.
///
/// Five plain members — nothing here is optional, so an implementation that
/// omitted a zero would be emitting a document the daemon never produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetNetStatsResponse {
    pub status: RpcStatus,
    /// Unix seconds: when this daemon's core started.
    pub start_time: u64,
    pub total_packets_in: u64,
    pub total_bytes_in: u64,
    pub total_packets_out: u64,
    pub total_bytes_out: u64,
}

/// Request body of `GET|POST /get_peer_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPeerListRequest {
    /// Ask the p2p layer for the *public* peerlist rather than the whole one.
    /// `OPT(true)`: omitted when true, which is the daemon's default answer.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub public_only: bool,
    /// Include peers whose host is currently blocked. `OPT(false)`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub include_blocked: bool,
}

impl Default for GetPeerListRequest {
    fn default() -> Self {
        Self {
            public_only: true,
            include_blocked: false,
        }
    }
}

const fn yes() -> bool {
    true
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_true(b: &bool) -> bool {
    *b
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// One peerlist entry.
///
/// `host` means three different things depending on the address arm the
/// daemon built it from — the ip string for ipv4, the bare host for ipv6, and
/// the whole `address:port` rendering for anything else (tor, i2p). That
/// branch is resolved daemon-side, so this type carries a string and no
/// discriminator; `ip` and `port` are zero on the arms that do not carry
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: u64,
    pub host: String,
    /// The ipv4 address with its four octets in **network** order — a
    /// **number**, unlike [`ConnectionInfo::ip`], which carries the same
    /// address as a dotted string. `10.32.0.7` is `117448714`
    /// (`0x0700_200a`); the pair appears together in
    /// `tests/vectors/rpc/get_peer_list_v1.json`. Zero for every non-ipv4
    /// arm.
    pub ip: u32,
    pub port: u16,
    pub last_seen: u64,
    /// `OPT(0)`: absent for an unpruned peer.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pruning_seed: u32,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
const fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Response of `GET|POST /get_peer_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPeerListResponse {
    pub status: RpcStatus,
    /// Omitted entirely when empty, as epee omits an empty sequence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub white_list: Vec<Peer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gray_list: Vec<Peer>,
}

/// The protocol state a connection is in, as the wire names it.
///
/// A **type**, not the C++ string: the daemon exports the raw enum value and
/// this is the one place it becomes a name, so an unmapped value cannot
/// silently render as some other state's name. [`ConnectionState::Unknown`]
/// is the C++ `default:` arm made explicit — it exists because the enum is
/// carried across an ABI, not because any state is expected to reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    BeforeHandshake,
    Synchronizing,
    Standby,
    Normal,
    Unknown,
}

impl ConnectionState {
    /// The name this state carries on the wire.
    ///
    /// Deliberately a second spelling of what `rename_all = "snake_case"`
    /// produces, because the console prints the name and `Debug` would give
    /// it `beforehandshake` where the same daemon's JSON says
    /// `before_handshake`. The duplication is bounded by
    /// `every_state_name_matches_its_serialization`, which asserts the two
    /// agree for every variant — so this cannot drift from the wire without
    /// a test going red.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeHandshake => "before_handshake",
            Self::Synchronizing => "synchronizing",
            Self::Standby => "standby",
            Self::Normal => "normal",
            Self::Unknown => "unknown",
        }
    }
}

impl From<u8> for ConnectionState {
    /// Mirrors `get_protocol_state_string`, including its `default:` arm.
    fn from(raw: u8) -> Self {
        match raw {
            0 => Self::BeforeHandshake,
            1 => Self::Synchronizing,
            2 => Self::Standby,
            3 => Self::Normal,
            _ => Self::Unknown,
        }
    }
}

/// One live p2p connection.
///
/// Every elapsed value here is **derived**, computed against a single instant
/// captured with the connection list rather than read per-field: the C++ this
/// replaces called `time(NULL)` twice per connection, so `live_time` and the
/// divisor behind `avg_download` / `avg_upload` could come from different
/// seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionInfo {
    pub incoming: bool,
    pub localhost: bool,
    pub local_ip: bool,
    /// `network_address::str()`: `host:port` for ipv4, the onion for tor.
    pub address: String,
    /// The host alone.
    pub host: String,
    /// A **string**, unlike [`Peer::ip`], and empty for every non-ipv4 arm.
    pub ip: String,
    /// A string too, and empty for every non-ipv4 arm.
    pub port: String,
    /// The peer id as 16 lowercase hex characters.
    pub peer_id: String,
    /// Bytes received, absolute.
    pub recv_count: u64,
    /// Seconds since the last receive, floored at the connection's age.
    pub recv_idle_time: u64,
    pub send_count: u64,
    pub send_idle_time: u64,
    pub state: ConnectionState,
    /// Seconds since the connection was established.
    pub live_time: u64,
    /// KiB/s over the connection's whole life.
    pub avg_download: u64,
    /// KiB/s right now.
    pub current_download: u64,
    pub avg_upload: u64,
    pub current_upload: u64,
    pub support_flags: u32,
    /// The connection uuid as 32 lowercase hex characters.
    pub connection_id: String,
    /// The peer's claimed blockchain height.
    pub height: u64,
    pub pruning_seed: u32,
    /// epee address type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
}

/// Result of the `get_connections` JSON-RPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetConnectionsResponse {
    pub status: RpcStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<ConnectionInfo>,
}

/// A `sync_info` peer: the same [`ConnectionInfo`], nested under `info`.
///
/// The nesting is the wire's, not a modelling choice — `sync_info` carries a
/// one-member wrapper struct where `get_connections` carries the object
/// directly, and `sync_info_v1.json` pins both in one capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncInfoPeer {
    pub info: ConnectionInfo,
}

/// One span of the block-download queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSpan {
    pub start_block_height: u64,
    pub nblocks: u64,
    /// The connection uuid as 32 lowercase hex characters.
    pub connection_id: String,
    /// Bytes/s, rounded half up.
    pub rate: u32,
    /// A percentage: the queue's 0..1 speed times 100, rounded half up.
    pub speed: u32,
    /// Bytes held for this span.
    pub size: u64,
    pub remote_address: String,
}

/// Result of the `sync_info` JSON-RPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncInfoResponse {
    pub status: RpcStatus,
    /// Chain height: top block height plus one.
    pub height: u64,
    /// `0` when the node considers itself synchronized.
    pub target_height: u64,
    /// The wire name is a **misnomer carried on purpose**: the value is a
    /// pruning *stripe*, not a seed. Renaming it is RK-W's business, where
    /// wire cleanup happens with a version bump and every client in one PR.
    pub next_needed_pruning_seed: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<SyncInfoPeer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spans: Vec<SyncSpan>,
    /// An ASCII picture of the download queue — `"[]"` when it is empty. A
    /// *string* holding brackets, not an empty array.
    pub overview: String,
}

#[cfg(test)]
mod tests {
    use super::ConnectionState;

    /// `as_str` and serde must agree for every variant. The console prints
    /// the first and the wire carries the second, and a daemon that answered
    /// `normal` over JSON while printing something else on its own console
    /// would be describing one connection two ways.
    #[test]
    fn every_state_name_matches_its_serialization() {
        for state in [
            ConnectionState::BeforeHandshake,
            ConnectionState::Synchronizing,
            ConnectionState::Standby,
            ConnectionState::Normal,
            ConnectionState::Unknown,
        ] {
            let serialized = serde_json::to_string(&state).expect("serialize");
            assert_eq!(format!("\"{}\"", state.as_str()), serialized, "{state:?}");
        }
    }
}
