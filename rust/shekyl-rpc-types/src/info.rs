// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_info` — the RK-5c slice of the daemon RPC KV cutover
//! (`docs/design/DAEMON_RPC_KV_GET_INFO.md` §4.1, RK-D18).
//!
//! # One reply, built from parts
//!
//! [`GetInfoResponse`] is composed of named parts, and each part is seen
//! under exactly one grant of the RPC channel round (`RPC_CHANNEL.md` §6.1):
//!
//! | Part | Grant |
//! |---|---|
//! | [`InfoHealth`], [`InfoIdentity`] | `health` |
//! | [`InfoChain`], [`InfoEconomics`] | `chain` |
//! | [`InfoPool`] | `pool` |
//! | [`InfoStatus`] | `status` |
//! | [`InfoPeers`] | `peers` |
//!
//! The parts are flattened onto one JSON object. The two outside the `view`
//! preset are carried as [`Hidden`], which is the part or its absence.
//!
//! # One field, one value
//!
//! The wire repeats values: `block_size_limit` beside `block_weight_limit`,
//! a 128-bit difficulty as three members, a network as a string and three
//! booleans. A part holds each value **once** and the repeats are produced
//! on the way out and checked on the way in — a reply whose two names for
//! one value disagree does not decode.
//!
//! # How the composition is written
//!
//! serde does not support `deny_unknown_fields` together with `flatten`, and
//! every reply in this crate refuses unknown keys. So both directions go
//! through one private flat struct, [`GetInfoWire`], which is the wire: it
//! names every key, refuses any other, and is converted to and from the
//! parts. The whole-part rule of [`Hidden`] lives in that conversion.
//!
//! # At parity nothing is absent yet
//!
//! A restricted reply today carries every key, with stand-ins for what it
//! does not disclose: zeroed counts, `free_space` as `u64::MAX`, an empty
//! `version`, and `database_size` rounded up to 5 GiB. That last one is
//! derived from a real read, so no constant written for an absent part could
//! reproduce it. Until the commit that makes a restricted reply omit them
//! (RK-Q8), the handler builds a restricted caller's Status and Peers as
//! present parts holding those stand-ins, and [`Hidden::Withheld`] is reached
//! only by decoding.

use serde::{Deserialize, Serialize};

use crate::chain::RpcStatus;
use crate::consensus_digest::DaemonNetwork;
use crate::hash::HashHex;
use crate::nullable::Nullable;

/// A part of a reply that a caller may be refused: the part, or its absence.
///
/// **A part is wholly present or wholly absent.** A decoder that built a
/// part from whichever of its keys happened to arrive would read a reply
/// that lost one key to contract drift as "withheld" — drift turned into a
/// disclosure decision. So a reply carrying some of a hidden part's keys and
/// not others does not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hidden<T> {
    /// The caller was shown the part.
    Shown(T),
    /// The part is not disclosed to this caller: none of its keys are on
    /// the wire.
    Withheld,
}

impl<T> Hidden<T> {
    /// The part, if the caller was shown it.
    pub const fn shown(&self) -> Option<&T> {
        match self {
            Self::Shown(part) => Some(part),
            Self::Withheld => None,
        }
    }
}

/// Whether this node is usable now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoHealth {
    /// The chain count: the top block's height plus one.
    pub height: u64,
    pub top_block_hash: HashHex,
    /// The core's target, `null` when the core reports none (RK-D15,
    /// RK-Q7). It is information: a synchronized node reports its target
    /// too, and whether the node is synchronized is [`Self::synchronized`]
    /// alone. The target comes from heights peers claim, so nothing is
    /// decided from it.
    pub target_height: Nullable<u64>,
    pub synchronized: bool,
    pub busy_syncing: bool,
    pub offline: bool,
    /// The node is knowingly not following the heaviest chain it has seen
    /// (C2-R1b F-1(a)); sticky for the life of the process.
    pub following_degraded: bool,
}

/// Which network and protocol this daemon speaks. `get_version` is the
/// identity source; these repeat it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoIdentity {
    /// On the wire as `nettype` and as the three booleans `mainnet`,
    /// `testnet`, `stagenet` (all false on a fakechain).
    pub nettype: DaemonNetwork,
    pub protocol_version: u64,
}

/// The chain's own figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoChain {
    /// Difficulty of the next block. On the wire as `difficulty` (low 64
    /// bits), `wide_difficulty` (`0x`-prefixed hex) and `difficulty_top64`.
    pub difficulty: u128,
    /// Cumulative difficulty at the tip, on the wire as the same triple.
    pub cumulative_difficulty: u128,
    /// The difficulty target, in seconds.
    pub target: u64,
    /// Transactions on the chain, coinbases excluded.
    pub tx_count: u64,
    /// On the wire as `block_weight_limit` and `block_size_limit`.
    pub block_weight_limit: u64,
    /// On the wire as `block_weight_median` and `block_size_median`.
    pub block_weight_median: u64,
    pub adjusted_time: u64,
}

/// The economics projection at the tip. The economics lane owns what these
/// mean (RK-D16); this is how they are carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoEconomics {
    /// Gross coins emitted through the tip, in atomic units. Net circulating
    /// supply is this minus [`Self::total_burned`].
    pub already_generated_coins: u64,
    pub release_multiplier: u64,
    /// The percentage the next coinbase burns. `0` when the computation
    /// refused; RK-Q9 turns that refusal into a fault.
    pub burn_pct: u64,
    pub total_burned: u64,
    pub staker_emission_share_effective: u64,
}

/// The pool, as far as this reply goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoPool {
    /// Entries in the pool. Today the count depends on who asks: the
    /// broadcast set for a restricted caller, every entry for any other.
    /// RK-Q10 splits it.
    pub tx_pool_size: u64,
}

/// What describes this node and not the network: its build, its uptime, its
/// disk, its connectivity posture, the forks it saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoStatus {
    pub start_time: u64,
    pub free_space: u64,
    pub database_size: u64,
    pub version: String,
    pub outgoing_connections_count: u64,
    pub incoming_connections_count: u64,
    pub alt_blocks_count: u64,
    pub rpc_connections_count: u64,
}

/// Per-connector transport and peerlist detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoPeers {
    pub public_incoming_socket_count: u64,
    pub public_outgoing_socket_count: u64,
    pub tor_incoming_socket_count: u64,
    pub tor_outgoing_socket_count: u64,
    pub white_peerlist_size: u64,
    pub grey_peerlist_size: u64,
}

/// Result of `get_info` (REST `/get_info`, `/getinfo`; JSON-RPC `get_info`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "GetInfoWire", into = "GetInfoWire")]
pub struct GetInfoResponse {
    pub status: RpcStatus,
    pub health: InfoHealth,
    pub identity: InfoIdentity,
    pub chain: InfoChain,
    pub economics: InfoEconomics,
    pub pool: InfoPool,
    /// The node-status part. Named `node` because `status` is the reply's
    /// [`RpcStatus`], as on every method.
    pub node: Hidden<InfoStatus>,
    pub peers: Hidden<InfoPeers>,
    /// Whether the caller was answered as a restricted one. Transitional:
    /// the RPC channel's handshake returns the grant instead (RT-W10).
    pub restricted: bool,
}

/// Why a document with `get_info`'s keys is not a `get_info` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetInfoShapeError {
    /// Some of a hidden part's keys arrived and others did not.
    PartialPart {
        part: &'static str,
        missing: &'static str,
    },
    /// Two wire names for one value disagree.
    Disagreement { value: &'static str, detail: String },
}

impl core::fmt::Display for GetInfoShapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PartialPart { part, missing } => write!(
                f,
                "the {part} part arrived without `{missing}`: a part is wholly present or \
                 wholly absent"
            ),
            Self::Disagreement { value, detail } => {
                write!(f, "the reply's names for {value} disagree: {detail}")
            }
        }
    }
}

impl std::error::Error for GetInfoShapeError {}

/// The wire: every key `get_info` carries, and no other.
///
/// Field order is immaterial (the parity suite compares parsed values). The
/// hidden parts' keys are optional here so that the conversion, not serde,
/// decides what a missing one means.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetInfoWire {
    status: RpcStatus,

    // Health.
    height: u64,
    top_block_hash: HashHex,
    target_height: Nullable<u64>,
    synchronized: bool,
    busy_syncing: bool,
    offline: bool,
    following_degraded: bool,

    // Identity.
    nettype: DaemonNetwork,
    mainnet: bool,
    testnet: bool,
    stagenet: bool,
    protocol_version: u64,

    // Chain.
    difficulty: u64,
    wide_difficulty: String,
    difficulty_top64: u64,
    cumulative_difficulty: u64,
    wide_cumulative_difficulty: String,
    cumulative_difficulty_top64: u64,
    target: u64,
    tx_count: u64,
    block_size_limit: u64,
    /// `KV_SERIALIZE_OPT(block_weight_limit, 0)`.
    #[serde(default, skip_serializing_if = "is_zero")]
    block_weight_limit: u64,
    block_size_median: u64,
    /// `KV_SERIALIZE_OPT(block_weight_median, 0)`.
    #[serde(default, skip_serializing_if = "is_zero")]
    block_weight_median: u64,
    adjusted_time: u64,

    // Economics.
    already_generated_coins: u64,
    release_multiplier: u64,
    burn_pct: u64,
    total_burned: u64,
    staker_emission_share_effective: u64,

    // Pool.
    tx_pool_size: u64,

    // Status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    free_space: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    database_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outgoing_connections_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incoming_connections_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alt_blocks_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpc_connections_count: Option<u64>,

    // Peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_incoming_socket_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_outgoing_socket_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tor_incoming_socket_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tor_outgoing_socket_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    white_peerlist_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grey_peerlist_size: Option<u64>,

    restricted: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
const fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// A 128-bit value as the wire's triple: low 64 bits, `0x`-prefixed minimal
/// lowercase hex, high 64 bits.
fn split_128(value: u128) -> (u64, String, u64) {
    let low = u64::try_from(value & u128::from(u64::MAX)).expect("masked to 64 bits");
    let top = u64::try_from(value >> 64).expect("shifted to 64 bits");
    (low, format!("0x{value:x}"), top)
}

/// The triple back to its one value, refusing a triple that names two.
fn join_128(
    value: &'static str,
    low: u64,
    wide: &str,
    top: u64,
) -> Result<u128, GetInfoShapeError> {
    let joined = (u128::from(top) << 64) | u128::from(low);
    let parsed = wide
        .strip_prefix("0x")
        .and_then(|hex| u128::from_str_radix(hex, 16).ok());
    if parsed == Some(joined) {
        Ok(joined)
    } else {
        Err(GetInfoShapeError::Disagreement {
            value,
            detail: format!("low {low}, top {top}, wide {wide:?}"),
        })
    }
}

/// One value under a second wire name must equal the first.
fn same(value: &'static str, first: u64, second: u64) -> Result<u64, GetInfoShapeError> {
    if first == second {
        Ok(first)
    } else {
        Err(GetInfoShapeError::Disagreement {
            value,
            detail: format!("{first} and {second}"),
        })
    }
}

/// Build a hidden part from its keys: all of them, or none.
///
/// Each key is paired with its wire name. `build` is handed the keys only
/// when every one arrived.
macro_rules! hidden_part {
    ($part:literal, [$($key:ident),+ $(,)?], $build:expr) => {{
        let present = [$($key.is_some()),+];
        if present.iter().all(|p| !*p) {
            Hidden::Withheld
        } else {
            $(
                let Some($key) = $key else {
                    return Err(GetInfoShapeError::PartialPart {
                        part: $part,
                        missing: stringify!($key),
                    });
                };
            )+
            Hidden::Shown($build)
        }
    }};
}

impl TryFrom<GetInfoWire> for GetInfoResponse {
    type Error = GetInfoShapeError;

    fn try_from(wire: GetInfoWire) -> Result<Self, Self::Error> {
        let GetInfoWire {
            status,
            height,
            top_block_hash,
            target_height,
            synchronized,
            busy_syncing,
            offline,
            following_degraded,
            nettype,
            mainnet,
            testnet,
            stagenet,
            protocol_version,
            difficulty,
            wide_difficulty,
            difficulty_top64,
            cumulative_difficulty,
            wide_cumulative_difficulty,
            cumulative_difficulty_top64,
            target,
            tx_count,
            block_size_limit,
            block_weight_limit,
            block_size_median,
            block_weight_median,
            adjusted_time,
            already_generated_coins,
            release_multiplier,
            burn_pct,
            total_burned,
            staker_emission_share_effective,
            tx_pool_size,
            start_time,
            free_space,
            database_size,
            version,
            outgoing_connections_count,
            incoming_connections_count,
            alt_blocks_count,
            rpc_connections_count,
            public_incoming_socket_count,
            public_outgoing_socket_count,
            tor_incoming_socket_count,
            tor_outgoing_socket_count,
            white_peerlist_size,
            grey_peerlist_size,
            restricted,
        } = wire;

        let booleans = (
            nettype == DaemonNetwork::Mainnet,
            nettype == DaemonNetwork::Testnet,
            nettype == DaemonNetwork::Stagenet,
        );
        if (mainnet, testnet, stagenet) != booleans {
            return Err(GetInfoShapeError::Disagreement {
                value: "the network",
                detail: format!(
                    "nettype {:?}, mainnet {mainnet}, testnet {testnet}, stagenet {stagenet}",
                    nettype.as_str()
                ),
            });
        }

        let node = hidden_part!(
            "status",
            [
                start_time,
                free_space,
                database_size,
                version,
                outgoing_connections_count,
                incoming_connections_count,
                alt_blocks_count,
                rpc_connections_count,
            ],
            InfoStatus {
                start_time,
                free_space,
                database_size,
                version,
                outgoing_connections_count,
                incoming_connections_count,
                alt_blocks_count,
                rpc_connections_count,
            }
        );
        let peers = hidden_part!(
            "peers",
            [
                public_incoming_socket_count,
                public_outgoing_socket_count,
                tor_incoming_socket_count,
                tor_outgoing_socket_count,
                white_peerlist_size,
                grey_peerlist_size,
            ],
            InfoPeers {
                public_incoming_socket_count,
                public_outgoing_socket_count,
                tor_incoming_socket_count,
                tor_outgoing_socket_count,
                white_peerlist_size,
                grey_peerlist_size,
            }
        );

        Ok(Self {
            status,
            health: InfoHealth {
                height,
                top_block_hash,
                target_height,
                synchronized,
                busy_syncing,
                offline,
                following_degraded,
            },
            identity: InfoIdentity {
                nettype,
                protocol_version,
            },
            chain: InfoChain {
                difficulty: join_128(
                    "the next difficulty",
                    difficulty,
                    &wide_difficulty,
                    difficulty_top64,
                )?,
                cumulative_difficulty: join_128(
                    "the cumulative difficulty",
                    cumulative_difficulty,
                    &wide_cumulative_difficulty,
                    cumulative_difficulty_top64,
                )?,
                target,
                tx_count,
                block_weight_limit: same(
                    "the block weight limit",
                    block_weight_limit,
                    block_size_limit,
                )?,
                block_weight_median: same(
                    "the block weight median",
                    block_weight_median,
                    block_size_median,
                )?,
                adjusted_time,
            },
            economics: InfoEconomics {
                already_generated_coins,
                release_multiplier,
                burn_pct,
                total_burned,
                staker_emission_share_effective,
            },
            pool: InfoPool { tx_pool_size },
            node,
            peers,
            restricted,
        })
    }
}

impl From<GetInfoResponse> for GetInfoWire {
    fn from(reply: GetInfoResponse) -> Self {
        let GetInfoResponse {
            status,
            health,
            identity,
            chain,
            economics,
            pool,
            node,
            peers,
            restricted,
        } = reply;
        let (difficulty, wide_difficulty, difficulty_top64) = split_128(chain.difficulty);
        let (cumulative_difficulty, wide_cumulative_difficulty, cumulative_difficulty_top64) =
            split_128(chain.cumulative_difficulty);
        let node = node.shown().cloned();
        let peers = peers.shown().cloned();
        Self {
            status,
            height: health.height,
            top_block_hash: health.top_block_hash,
            target_height: health.target_height,
            synchronized: health.synchronized,
            busy_syncing: health.busy_syncing,
            offline: health.offline,
            following_degraded: health.following_degraded,
            nettype: identity.nettype,
            mainnet: identity.nettype == DaemonNetwork::Mainnet,
            testnet: identity.nettype == DaemonNetwork::Testnet,
            stagenet: identity.nettype == DaemonNetwork::Stagenet,
            protocol_version: identity.protocol_version,
            difficulty,
            wide_difficulty,
            difficulty_top64,
            cumulative_difficulty,
            wide_cumulative_difficulty,
            cumulative_difficulty_top64,
            target: chain.target,
            tx_count: chain.tx_count,
            block_size_limit: chain.block_weight_limit,
            block_weight_limit: chain.block_weight_limit,
            block_size_median: chain.block_weight_median,
            block_weight_median: chain.block_weight_median,
            adjusted_time: chain.adjusted_time,
            already_generated_coins: economics.already_generated_coins,
            release_multiplier: economics.release_multiplier,
            burn_pct: economics.burn_pct,
            total_burned: economics.total_burned,
            staker_emission_share_effective: economics.staker_emission_share_effective,
            tx_pool_size: pool.tx_pool_size,
            start_time: node.as_ref().map(|n| n.start_time),
            free_space: node.as_ref().map(|n| n.free_space),
            database_size: node.as_ref().map(|n| n.database_size),
            outgoing_connections_count: node.as_ref().map(|n| n.outgoing_connections_count),
            incoming_connections_count: node.as_ref().map(|n| n.incoming_connections_count),
            alt_blocks_count: node.as_ref().map(|n| n.alt_blocks_count),
            rpc_connections_count: node.as_ref().map(|n| n.rpc_connections_count),
            version: node.map(|n| n.version),
            public_incoming_socket_count: peers.as_ref().map(|p| p.public_incoming_socket_count),
            public_outgoing_socket_count: peers.as_ref().map(|p| p.public_outgoing_socket_count),
            tor_incoming_socket_count: peers.as_ref().map(|p| p.tor_incoming_socket_count),
            tor_outgoing_socket_count: peers.as_ref().map(|p| p.tor_outgoing_socket_count),
            white_peerlist_size: peers.as_ref().map(|p| p.white_peerlist_size),
            grey_peerlist_size: peers.as_ref().map(|p| p.grey_peerlist_size),
            restricted,
        }
    }
}
