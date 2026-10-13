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
//! The wire says each value once, and so does a part. The last repeat was
//! the network, a string and three booleans, which went at 3.54 (RK-Q6):
//! `get_version` is where a daemon names its network, and this reply no
//! longer carries it under any name.
//!
//! The other repeats went at 3.52 (RK-Q1). A difficulty was three members:
//! its low 64 bits, a `0x` hex string, and its high 64 bits. It is the hex
//! string alone, a [`HexU128`], whose parser is strict because nothing
//! beside it checks it any more. The block weight limit and median were
//! each under a `size` name too; the `weight` names are the ones kept, and
//! they are always present: `0` is a value (RK-D23).
//!
//! # How the composition is written
//!
//! serde does not support `deny_unknown_fields` together with `flatten`, and
//! every reply in this crate refuses unknown keys. So both directions go
//! through one private flat struct, [`GetInfoWire`], which is the wire: it
//! names every key, refuses any other, and is converted to and from the
//! parts. The whole-part rule of [`Hidden`] lives in that conversion.
//!
//! # A part the caller is not shown is absent
//!
//! A reply to a caller who is not shown Status or Peers does not carry
//! those parts: none of their keys is on the wire, and the reply decodes
//! with the part [`Hidden::Withheld`] (RK-Q8, `CORE_RPC_VERSION` 3.48).
//!
//! Until then such a reply carried every key, with stand-ins for what it
//! did not disclose: zeroed counts, `free_space` as `u64::MAX`, an empty
//! `version`, and `database_size` rounded up to 5 GiB. Each was a value
//! that meant "not this value", and a reader could not tell it from an
//! answer: a wallet read the zeroed connection counts as a node with no
//! peers. A reader of a hidden part now asks [`Hidden::shown`] and is told
//! when there is nothing to read.

use serde::{Deserialize, Serialize};
use shekyl_units::{AtomicUnits, AtomicUnitsString};

use crate::chain::RpcStatus;
use crate::hash::HashHex;
use crate::hex128::HexU128;
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
    /// Whether this node has at least one peer it can relay through: a
    /// session that has finished its handshake, on any connector (RK-D14,
    /// RK-Q4).
    ///
    /// Health, so every caller is told. It is a boolean and never a count:
    /// how many peers a node has describes the node and belongs to Status,
    /// which a daemon may withhold. A reader that wants "can this node
    /// relay" reads this, and never infers it from the Status counts.
    pub has_peers: bool,
}

/// Which protocol this daemon speaks.
///
/// The network is not here. `get_version` is the identity source, and until
/// 3.54 this reply repeated its `nettype` four times over: as a string and
/// as the booleans `mainnet`, `testnet`, `stagenet` (RK-Q6). A reader that
/// wants the daemon's network reads `get_version`, through
/// [`crate::IdentityExpectation::read`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoIdentity {
    pub protocol_version: u64,
}

/// The chain's own figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoChain {
    /// Difficulty of the next block. On the wire as `wide_difficulty`, a
    /// [`HexU128`].
    pub difficulty: u128,
    /// Cumulative difficulty at the tip. On the wire as
    /// `wide_cumulative_difficulty`, a [`HexU128`].
    pub cumulative_difficulty: u128,
    /// The difficulty target, in seconds.
    pub target: u64,
    /// Transactions on the chain, coinbases excluded.
    pub tx_count: u64,
    /// On the wire as `block_weight_limit`. Always present.
    pub block_weight_limit: u64,
    /// On the wire as `block_weight_median`. Always present.
    pub block_weight_median: u64,
    pub adjusted_time: u64,
}

/// The economics projection at the tip. The economics lane owns what these
/// mean (RK-D16); this is how they are carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoEconomics {
    /// Gross coins emitted through the tip. Net circulating supply is this
    /// minus [`Self::total_burned`]. On the wire as a decimal string of
    /// atomic units (RK-Q2).
    pub already_generated_coins: AtomicUnits,
    pub release_multiplier: u64,
    /// The percentage the next coinbase burns, fixed-point. `0` is a burn
    /// of nothing; a computation that refuses is a fault, not a value
    /// (RK-Q9).
    pub burn_pct: u64,
    /// Cumulative coins destroyed through the tip. On the wire as a decimal
    /// string of atomic units (RK-Q2).
    pub total_burned: AtomicUnits,
    pub staker_emission_share_effective: u64,
}

/// The pool, as far as this reply goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoPool {
    /// Pool entries this node has **broadcast**. One quantity, for every
    /// caller.
    ///
    /// An entry this node holds and has not yet broadcast is not counted
    /// here, whoever asks: it is in [`InfoHost`]. That includes a
    /// transaction on its stem, which has been relayed to one peer and not
    /// broadcast. Until 3.50 this member was the broadcast set for a
    /// restricted caller and every entry for any other (RK-Q10).
    pub tx_pool_size: u64,
}

/// What only the host's own administrator is told (`RPC_CHANNEL.md` §6.1,
/// RT-O9.3). It belongs to no grant, `admin` included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoHost {
    /// Pool entries this node holds and has **not yet broadcast**: its own
    /// transactions and the ones it is carrying on a stem. Whether such an
    /// entry exists says where a transaction originated, which is what the
    /// relay's stem phase hides, so it is told to nobody else.
    pub tx_pool_unbroadcast_count: u64,
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
    /// The host-only part: withheld from every caller but the host's
    /// administrator.
    pub host: Hidden<InfoHost>,
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
    /// The Status part is shown and its `version` is empty. An empty
    /// string was what a restricted reply wrote for "not disclosed" until
    /// 3.48; a reply that does not disclose the version now withholds the
    /// part. A shown part names the build, so an empty one is not an
    /// answer and is not read as "undisclosed" (RK-D23).
    EmptyVersion,
}

impl core::fmt::Display for GetInfoShapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PartialPart { part, missing } => write!(
                f,
                "the {part} part arrived without `{missing}`: a part is wholly present or \
                 wholly absent"
            ),
            Self::EmptyVersion => f.write_str(
                "the status part carries an empty `version`: a shown part names the build, \
                 and a reply that does not disclose it withholds the part",
            ),
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
    has_peers: bool,

    // Identity.
    protocol_version: u64,

    // Chain.
    wide_difficulty: HexU128,
    wide_cumulative_difficulty: HexU128,
    target: u64,
    tx_count: u64,
    // Required, and written at `0`: a limit or median of zero is a value.
    // The C++ serializer omitted both at zero, and a reader defaulted them.
    block_weight_limit: u64,
    block_weight_median: u64,
    adjusted_time: u64,

    // Economics.
    // Amounts of coin: decimal strings, the wallet contract's encoding. A
    // JSON number loses integers above 2^53 in a JavaScript reader, and the
    // emission asymptote is far past that. Required: no default, since the
    // type's own default is zero and a missing key must not read as it.
    already_generated_coins: AtomicUnitsString,
    release_multiplier: u64,
    burn_pct: u64,
    total_burned: AtomicUnitsString,
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

    // Host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tx_pool_unbroadcast_count: Option<u64>,

    restricted: bool,
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
            has_peers,
            protocol_version,
            wide_difficulty,
            wide_cumulative_difficulty,
            target,
            tx_count,
            block_weight_limit,
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
            tx_pool_unbroadcast_count,
            restricted,
        } = wire;

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
        if node.shown().is_some_and(|status| status.version.is_empty()) {
            return Err(GetInfoShapeError::EmptyVersion);
        }
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
        let host = hidden_part!(
            "host",
            [tx_pool_unbroadcast_count],
            InfoHost {
                tx_pool_unbroadcast_count,
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
                has_peers,
            },
            identity: InfoIdentity { protocol_version },
            chain: InfoChain {
                difficulty: wide_difficulty.get(),
                cumulative_difficulty: wide_cumulative_difficulty.get(),
                target,
                tx_count,
                block_weight_limit,
                block_weight_median,
                adjusted_time,
            },
            economics: InfoEconomics {
                already_generated_coins: already_generated_coins.to_atomic_units(),
                release_multiplier,
                burn_pct,
                total_burned: total_burned.to_atomic_units(),
                staker_emission_share_effective,
            },
            pool: InfoPool { tx_pool_size },
            node,
            peers,
            host,
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
            host,
            restricted,
        } = reply;
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
            has_peers: health.has_peers,
            protocol_version: identity.protocol_version,
            wide_difficulty: HexU128(chain.difficulty),
            wide_cumulative_difficulty: HexU128(chain.cumulative_difficulty),
            target: chain.target,
            tx_count: chain.tx_count,
            block_weight_limit: chain.block_weight_limit,
            block_weight_median: chain.block_weight_median,
            adjusted_time: chain.adjusted_time,
            already_generated_coins: economics.already_generated_coins.into(),
            release_multiplier: economics.release_multiplier,
            burn_pct: economics.burn_pct,
            total_burned: economics.total_burned.into(),
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
            tx_pool_unbroadcast_count: host.shown().map(|h| h.tx_pool_unbroadcast_count),
            restricted,
        }
    }
}
