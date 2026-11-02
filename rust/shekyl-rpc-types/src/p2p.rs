// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The p2p-facing read methods — the RK-5a slice of the daemon RPC KV
//! cutover (`docs/completed/DAEMON_RPC_KV_CUTOVER.md` §3.1).
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
/// the whole `address:port` rendering for Tor. That
/// branch is resolved daemon-side, so this type carries a string and no
/// discriminator; `ip` and `port` are zero on the arms that do not carry
/// them.
///
/// No `last_seen` (3.55): the Rust peer lists carry no clock in what they
/// disclose or list (`P2P_3_SLICE_1_PEERLIST_BRIEF.md` §4, ruled
/// 2026-10-09), so there is no value to report and none is invented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub host: String,
    /// The ipv4 address with its four octets in **network** order — a
    /// **number**, unlike [`ConnectionInfo::ip`], which carries the same
    /// address as a dotted string. `10.32.0.7` is `117448714`
    /// (`0x0700_200a`); the pair appears together in
    /// `tests/vectors/rpc/get_peer_list_v4.json`. Zero for every non-ipv4
    /// arm.
    pub ip: u32,
    pub port: u16,
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

/// What chain sync is doing with a session: its header run's mode (3.64).
///
/// A session with no header run is [`SyncMode::Idle`]; it may still serve
/// bodies. The names are the sync owner's (`shekyl_chain_sync::SessionMode`),
/// which the node maps one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// No header run.
    Idle,
    /// In cap; a proved header joins the verified tree.
    Reachable,
    /// The long-run slot; headers stay off the tree until they beat the best chain.
    Slot,
    /// Verifying a prefix to compare with the slot holder.
    Challenging,
    /// Past the reorg cap, not hashed.
    PastCap,
    /// Past the cap and heavier than the local chain, waiting for the draw.
    EvidenceCandidate,
    /// The evidence check.
    Evidence,
}

impl SyncMode {
    /// The name this mode carries on the wire, which the console prints.
    /// `every_mode_name_matches_its_serialization` holds the two together.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Reachable => "reachable",
            Self::Slot => "slot",
            Self::Challenging => "challenging",
            Self::PastCap => "past_cap",
            Self::EvidenceCandidate => "evidence_candidate",
            Self::Evidence => "evidence",
        }
    }
}

/// Chain sync's derived state, as the wire names it (3.64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainSyncState {
    /// No session has completed a handshake.
    NoView,
    /// The local chain has less work than the best verified chain.
    Behind,
    /// On the best verified chain, while the backward fill is short.
    Following,
    /// On the best verified chain, and the fill has reached its checkpoint.
    Synced,
}

impl ChainSyncState {
    /// The name this state carries on the wire, which the console prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoView => "no_view",
            Self::Behind => "behind",
            Self::Following => "following",
            Self::Synced => "synced",
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
    /// Bytes received, absolute.
    pub recv_count: u64,
    /// Seconds since the last receive, floored at the connection's age.
    pub recv_idle_time: u64,
    pub send_count: u64,
    pub send_idle_time: u64,
    /// What chain sync is doing with the session (3.64). JSON null for a
    /// session chain sync does not hold, such as one before its handshake.
    pub state: Option<SyncMode>,
    /// Seconds since the connection was established.
    pub live_time: u64,
    /// KiB/s over the connection's whole life.
    pub avg_download: u64,
    /// KiB/s right now.
    pub current_download: u64,
    pub avg_upload: u64,
    pub current_upload: u64,
    /// The connection uuid as 32 lowercase hex characters.
    pub connection_id: String,
    /// The block count the peer claims, from chain sync's view (3.64).
    /// JSON null before it has claimed. Zero would read as a real claim.
    pub height: Option<u64>,
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

/// A header request in flight to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncHeaderRequest {
    /// Milliseconds since it was sent.
    pub age_ms: u64,
    /// Milliseconds until its response is late; 0 once it is.
    pub due_in_ms: u64,
}

/// A body span in flight to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncBodyRequest {
    /// The height of its first block.
    pub start_height: u64,
    /// How many blocks it asks for.
    pub count: u64,
    /// The response budget its deadline is planned for, in bytes.
    pub planned_bytes: u64,
    /// Milliseconds since it was sent.
    pub age_ms: u64,
    /// Milliseconds until its response is late; 0 once it is.
    pub due_in_ms: u64,
}

/// One session in `sync_info` (3.64): who it is and what chain sync is
/// doing with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncInfoPeer {
    /// The connection uuid as 32 lowercase hex characters, as
    /// [`ConnectionInfo::connection_id`] renders it.
    pub connection_id: String,
    /// `host:port` for ipv4, the onion for tor.
    pub address: String,
    /// The block count the peer claims; null before it has claimed.
    pub claimed_height: Option<u64>,
    /// What its header run is doing.
    pub mode: SyncMode,
    /// The header request in flight to it, null when none is.
    pub header_request: Option<SyncHeaderRequest>,
    /// The body spans in flight to it. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_requests: Vec<SyncBodyRequest>,
    /// Bytes per second its last header or body response arrived at; null
    /// until one has.
    pub rate: Option<u64>,
}

/// Result of the `sync_info` JSON-RPC method (3.64): chain sync's view.
/// Whether the node is syncing, toward what, from whom and how fast, and
/// whether it is stuck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncInfoResponse {
    pub status: RpcStatus,
    /// The local chain's block count: top block height plus one.
    pub height: u64,
    /// What sync works toward: the best verified chain's block count.
    /// Equal to `height` on the best chain.
    pub target_height: u64,
    /// Chain sync's derived state.
    pub state: ChainSyncState,
    /// Behind, with nothing moving toward the target: no session's chain
    /// serves what the node still needs.
    pub stalled: bool,
    /// One row per session chain sync holds. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<SyncInfoPeer>,
}

/// A reply about peers or connections, from a daemon that may have been
/// started offline (Rick, 2026-10-14; 3.56).
///
/// [`P2pReply::Offline`] is `{"status": "offline"}` and nothing else: the daemon
/// has no peers, connections or download queue by configuration, and an
/// empty list under `OK` would read as a running node that has none. The
/// decoder refuses a `offline` status beside any other member, and a running
/// reply whose status is `offline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pReply<T> {
    /// P2P runs; the method's reply.
    Running(T),
    /// The daemon was started offline.
    Offline,
}

impl<T> P2pReply<T> {
    /// The reply, when P2P runs.
    #[must_use]
    pub fn running(&self) -> Option<&T> {
        match self {
            Self::Running(reply) => Some(reply),
            Self::Offline => None,
        }
    }

    /// The reply by value, when P2P runs.
    #[must_use]
    pub fn into_running(self) -> Option<T> {
        match self {
            Self::Running(reply) => Some(reply),
            Self::Offline => None,
        }
    }
}

/// A reply type that can stand as [`P2pReply::Running`]: one with a status.
pub trait P2pRunningReply {
    /// The reply's status.
    fn status(&self) -> &RpcStatus;
}

impl P2pRunningReply for GetConnectionsResponse {
    fn status(&self) -> &RpcStatus {
        &self.status
    }
}

impl P2pRunningReply for GetPeerListResponse {
    fn status(&self) -> &RpcStatus {
        &self.status
    }
}

impl P2pRunningReply for SyncInfoResponse {
    fn status(&self) -> &RpcStatus {
        &self.status
    }
}

/// `{"status": "offline"}`, the whole of an offline reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfflineWire {
    status: OfflineStatus,
}

/// The one status an offline reply carries.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RpcStatus", into = "RpcStatus")]
struct OfflineStatus;

impl TryFrom<RpcStatus> for OfflineStatus {
    type Error = &'static str;

    fn try_from(status: RpcStatus) -> Result<Self, Self::Error> {
        if status.is_offline() {
            Ok(Self)
        } else {
            Err("not offline")
        }
    }
}

impl From<OfflineStatus> for RpcStatus {
    fn from(_: OfflineStatus) -> Self {
        Self::offline()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum P2pReplyWire<T> {
    Offline(OfflineWire),
    Running(T),
}

impl<T: Serialize> Serialize for P2pReply<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Running(reply) => reply.serialize(serializer),
            Self::Offline => OfflineWire {
                status: OfflineStatus,
            }
            .serialize(serializer),
        }
    }
}

impl<'de, T> Deserialize<'de> for P2pReply<T>
where
    T: Deserialize<'de> + P2pRunningReply,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match P2pReplyWire::<T>::deserialize(deserializer)? {
            P2pReplyWire::Offline(_) => Ok(Self::Offline),
            P2pReplyWire::Running(reply) if reply.status().is_offline() => {
                Err(serde::de::Error::custom(
                    "an offline reply carries no other member: an offline daemon \
                     reports no peer, connection or span",
                ))
            }
            P2pReplyWire::Running(reply) => Ok(Self::Running(reply)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainSyncState, SyncMode};

    /// `as_str` and serde agree for every mode and state. The console prints
    /// the first and the wire carries the second.
    #[test]
    fn every_mode_name_matches_its_serialization() {
        for mode in [
            SyncMode::Idle,
            SyncMode::Reachable,
            SyncMode::Slot,
            SyncMode::Challenging,
            SyncMode::PastCap,
            SyncMode::EvidenceCandidate,
            SyncMode::Evidence,
        ] {
            let serialized = serde_json::to_string(&mode).expect("serialize");
            assert_eq!(format!("\"{}\"", mode.as_str()), serialized, "{mode:?}");
        }
        for state in [
            ChainSyncState::NoView,
            ChainSyncState::Behind,
            ChainSyncState::Following,
            ChainSyncState::Synced,
        ] {
            let serialized = serde_json::to_string(&state).expect("serialize");
            assert_eq!(format!("\"{}\"", state.as_str()), serialized, "{state:?}");
        }
    }
}
