// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_info`, served natively (`docs/design/DAEMON_RPC_KV_GET_INFO.md`).
//!
//! Like [`crate::methods`], this is the method with no Axum, no FFI and no
//! JSON in it: facts in, a typed reply out.
//!
//! # Gathering by part
//!
//! The handler asks [`Disclosure`] which parts the caller is shown and reads
//! only those (RK-D24). Health, identity, chain, economics and the pool's
//! broadcast count are read for every caller. Status and Peers are read
//! only for a caller who is shown them, so a failure in one of those reads
//! — the volume that cannot be queried for its free space, say — cannot
//! refuse a caller who was never going to be told it.
//!
//! # Parity
//!
//! The method first answered exactly what the C++ handler it replaced
//! answered, and five oracle vectors captured from that handler's own
//! computation held it to that. Each later commit moves one thing off
//! parity, with a vector derived from its predecessor: the `target_height`
//! sentinel went first (RK-D15, 3.46), then `has_peers` arrived (RK-D14,
//! 3.47), then the restricted stand-ins went (RK-Q8, 3.48): a caller who is
//! not shown Status or Peers gets a reply without those parts, where it got
//! zeros, an empty version, `u64::MAX` of free space and the store's size
//! rounded up. It still writes what the design retires after that, each
//! marked where it is written: a refused burn computation reported as
//! zero, and a pool count whose meaning depends on the caller. The
//! connection counts went to the board at 3.49 (RK-Q3): handshaken
//! sessions on every connector, one snapshot with `has_peers`, and no
//! subtraction.
//!
//! **The store's size is a Status member and is read with Status.** While
//! a restricted reply carried it rounded, it was read for every caller, so
//! a store that could not be read for its size refused a caller who was
//! only ever going to be told a rounded figure. That exception ended with
//! the stand-ins: no read is now made for a caller who will not receive
//! what it returns.

use shekyl_economics::{project_at_tip, EconomicParams, TipOperands};
use shekyl_rpc_types::{
    GetInfoResponse, HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity,
    InfoPeers, InfoPool, InfoStatus, RpcStatus,
};

use crate::info_facts::{InfoFacts, PoolScope, SessionCounts};
use crate::methods::RpcFault;

/// What a caller is shown: which parts its grants select, and whether it is
/// the host's administrator.
///
/// Two axes, and the second is not a grant. Host-only data — on this reply,
/// the pool entries this node has not broadcast — is served to the host's
/// administrator and to no grant, `admin` included (`RPC_CHANNEL.md` §6.1,
/// RT-O9.3). Naming the axis here is what stops the channel's daemon slice
/// from reading "`admin`" as "may see unrelayed entries".
///
/// Today both axes are mapped from the one listener flag
/// ([`Self::from_listener`]). The RPC channel (RT-W10) maps a connection's
/// grant set and its host flag onto the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    /// The caller is shown the Status part.
    status: bool,
    /// The caller is shown the Peers part.
    peers: bool,
    /// The caller is the host's administrator.
    host: bool,
    /// The listener's posture, reported back as `restricted`. Transitional:
    /// it leaves with that field when the channel's handshake returns the
    /// grant instead.
    listener_restricted: bool,
}

impl Disclosure {
    /// The unrestricted listener: every part, and host. That listener binds
    /// loopback only, which is what stands in for a host identity until the
    /// channel exists.
    pub const FULL: Self = Self {
        status: true,
        peers: true,
        host: true,
        listener_restricted: false,
    };

    /// The restricted listener: the `view` parts, and not host.
    pub const VIEW: Self = Self {
        status: false,
        peers: false,
        host: false,
        listener_restricted: true,
    };

    /// The disclosure a listener's posture gives its callers.
    #[must_use]
    pub const fn from_listener(restricted: bool) -> Self {
        if restricted {
            Self::VIEW
        } else {
            Self::FULL
        }
    }
}

/// `get_info` (REST `/get_info`, `/getinfo`; JSON-RPC `get_info`).
///
/// `rpc_connections` is this server's live connection count, which the
/// transport owns; it is a Status field, so a caller who is not shown
/// Status is not told it.
///
/// # Errors
///
/// [`RpcFault::Facts`] when a read made on this caller's behalf fails. A
/// read that is not made cannot.
pub fn get_info(
    facts: &dyn InfoFacts,
    disclosure: Disclosure,
    rpc_connections: u64,
) -> Result<GetInfoResponse, RpcFault> {
    let chain = facts.chain()?;
    // The node's sessions, from one snapshot of the board. Health's
    // `has_peers` needs it, and Health is every caller's, so it is read for
    // every caller. The two connection counts in Status are the same read.
    //
    // An offline node is the one case where the board is not read. Offline
    // is configuration: the p2p layer was told not to start, so it binds no
    // hub, and "no sessions" is known without asking. That is a read
    // avoided, not a fault mapped: the branch is on what the node was
    // configured to be, and never on what the read returned.
    //
    // Everywhere else a hub that is not up is a fault and refuses the
    // reply: `false` and zero would be answers nobody gave.
    let sessions = if chain.offline {
        SessionCounts::NONE
    } else {
        facts.sessions()?
    };
    let has_peers = sessions.has_peers();
    let pool_count = facts.pool_count(if disclosure.host {
        PoolScope::All
    } else {
        PoolScope::Broadcast
    })?;
    // A part the caller is not shown is withheld: absent from the reply,
    // and none of its reads made (RK-D24, RK-Q8). No member is written with
    // a value that means "not this value".
    let node = if disclosure.status {
        let status = facts.status()?;
        Hidden::Shown(InfoStatus {
            start_time: status.start_time,
            free_space: status.free_space,
            database_size: facts.store_size()?,
            version: status.version,
            // Handshaken sessions on every connector, per direction: the
            // same sessions `has_peers` is about, from the same snapshot.
            // A socket before its handshake is in Peers' socket counts.
            outgoing_connections_count: sessions.outbound,
            incoming_connections_count: sessions.inbound,
            alt_blocks_count: status.alt_blocks_count,
            rpc_connections_count: rpc_connections,
        })
    } else {
        Hidden::Withheld
    };

    let peers = if disclosure.peers {
        let peers = facts.peers()?;
        Hidden::Shown(InfoPeers {
            public_incoming_socket_count: peers.public_incoming_sockets,
            public_outgoing_socket_count: peers.public_outgoing_sockets,
            tor_incoming_socket_count: peers.tor_incoming_sockets,
            tor_outgoing_socket_count: peers.tor_outgoing_sockets,
            white_peerlist_size: peers.white_peerlist_size,
            grey_peerlist_size: peers.grey_peerlist_size,
        })
    } else {
        Hidden::Withheld
    };

    let height = chain.chain_height.to_raw();
    let tip = project_at_tip(
        &TipOperands {
            coins_generated: chain.already_generated_coins,
            total_burned: chain.total_burned,
            tx_volume: chain.tx_volume,
            chain_height: height,
        },
        &EconomicParams::default(),
    );
    // Parity: a refused burn computation is reported as zero, and logged.
    // `0` % is a legitimate burn, so RK-Q9 turns this into a store fault.
    let burn_pct = tip.burn_pct.unwrap_or_else(|violation| {
        tracing::error!(
            %violation,
            "get_info: the burn computation refused; reporting burn_pct 0"
        );
        0
    });

    Ok(GetInfoResponse {
        status: RpcStatus::ok(),
        health: InfoHealth {
            height,
            top_block_hash: HashHex::from_bytes(*chain.top_hash.as_bytes()),
            // The core's target as the core reports it, synchronized or
            // not, and `null` when it has none (RK-D15).
            target_height: chain
                .core_target_height
                .map(shekyl_types::ChainCount::to_raw)
                .into(),
            synchronized: chain.synchronized,
            busy_syncing: chain.busy_syncing,
            offline: chain.offline,
            following_degraded: chain.following_degraded,
            has_peers,
        },
        identity: InfoIdentity {
            nettype: chain.nettype,
            protocol_version: chain.protocol_version,
        },
        chain: InfoChain {
            difficulty: chain.difficulty,
            cumulative_difficulty: chain.cumulative_difficulty,
            target: chain.difficulty_target,
            // Coinbases excluded: one per block. Unsigned, as the C++
            // handler computed it.
            tx_count: chain.total_transactions.wrapping_sub(height),
            block_weight_limit: chain.block_weight_limit,
            block_weight_median: chain.block_weight_median,
            adjusted_time: chain.adjusted_time,
        },
        economics: InfoEconomics {
            already_generated_coins: tip.coins_generated.to_raw(),
            release_multiplier: tip.release_multiplier,
            burn_pct,
            total_burned: tip.total_burned.to_raw(),
            staker_emission_share_effective: tip.staker_emission_share,
        },
        // Parity: one key, two quantities — the broadcast set for a caller
        // who is not host, every entry for one who is. RK-Q10 splits it.
        pool: InfoPool {
            tx_pool_size: pool_count,
        },
        node,
        peers,
        restricted: disclosure.listener_restricted,
    })
}

#[cfg(test)]
pub(crate) mod tests;
