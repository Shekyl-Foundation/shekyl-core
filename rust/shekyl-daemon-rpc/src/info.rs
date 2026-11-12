// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `daemon_status` (`RPC_WIRE.md`).
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
//! # What the reply carries
//!
//! `txpool_count` is the entries this node has broadcast, for every caller;
//! `txpool_private_count`, the entries it has not yet broadcast, is a
//! host-only part. The connection counts are the board's handshaken
//! sessions on every connector, from one snapshot. A store that holds more
//! burned than generated has contradicted itself, and the method refuses
//! with a fault that names the invariant and its operands. No member
//! carries a stand-in for "no value": a part the caller is not shown is
//! absent, and a value with no answer is `null`.
//!
//! **The store's size is a Status member and is read with Status.** While
//! a restricted reply carried it rounded, it was read for every caller, so
//! a store that could not be read for its size refused a caller who was
//! only ever going to be told a rounded figure. That exception ended with
//! the stand-ins: no read is now made for a caller who will not receive
//! what it returns.

use shekyl_economics::{project_at_tip, TipOperands};
use shekyl_rpc_types::hex128::HexU128;
use shekyl_rpc_types::kinds::{
    Count, Duration, Height, Integer, Micro, Size, Text, Time, Withheld,
};
use shekyl_rpc_types::wire::daemon::{ConnectorMap, DaemonStatus, GrantName};
use shekyl_rpc_types::HashHex;
use shekyl_units::wire::AtomicUnitsString;

use shekyl_rpc_types::method::{Grant, GrantSet, Preset};

use crate::chain_facts::{ChainFacts, FactsFault};
use crate::info_facts::{InfoFacts, PeerFacts, PoolScope, PoolState};
use crate::methods::{RpcFault, StoreFault};

/// What a caller is shown: which parts its grants select, and whether it is
/// the host's administrator.
///
/// Two axes, and the second is not a grant. Host-only data — on this reply,
/// the pool entries this node has not broadcast — is served to the host's
/// administrator and to no grant, `admin` included (`RPC_CHANNEL.md` §6.1,
/// RT-O9.3). Naming the axis here is what stops "`admin`" being read as "may
/// see entries not yet broadcast".
///
/// It is made from a connection's [`crate::authority::Authority`]
/// ([`Self::of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disclosure {
    /// The grants whose parts the caller is shown.
    grants: GrantSet,
    /// The caller is the host's administrator.
    host: bool,
}

impl Disclosure {
    /// Every part, and host: the host's administrator.
    pub const FULL: Self = Self {
        grants: GrantSet::ALL,
        host: true,
    };

    /// The `view` parts, and not host.
    pub const VIEW: Self = Self {
        grants: Preset::View.grants(),
        host: false,
    };

    /// The disclosure a connection holding `grants` is given.
    #[must_use]
    pub const fn of(grants: GrantSet, host: bool) -> Self {
        Self { grants, host }
    }

    /// Whether the part `grant` selects is shown.
    #[must_use]
    pub const fn shows(self, grant: Grant) -> bool {
        self.grants.holds(grant)
    }

    /// Whether the Status part is shown.
    #[must_use]
    pub const fn status(self) -> bool {
        self.shows(Grant::Status)
    }

    /// Whether the Peers part is shown.
    #[must_use]
    pub const fn peers(self) -> bool {
        self.shows(Grant::Peers)
    }

    /// Whether the Config rows are shown (RT-O24).
    #[must_use]
    pub const fn config(self) -> bool {
        self.shows(Grant::Config)
    }

    /// Whether the caller is the host's administrator.
    #[must_use]
    pub const fn host(self) -> bool {
        self.host
    }

    /// The grants the caller holds.
    #[must_use]
    pub const fn grants(self) -> GrantSet {
        self.grants
    }
}

/// `value` to a caller shown the Status part; withheld otherwise.
fn shown<T>(on: bool, value: T) -> Withheld<T> {
    if on {
        Withheld::Shown(value)
    } else {
        Withheld::Withheld
    }
}

/// `daemon_status`: the node's state, each part to a caller its grant
/// admits (`RPC_CHANNEL.md` §6.1). A part the caller is not shown is absent
/// and none of its reads is made (RK-D24), so a failure in one cannot
/// refuse a caller who was never going to be told it.
///
/// `rpc_connections` is this server's live connection count, which the
/// transport owns.
///
/// # Errors
///
/// [`RpcFault::Facts`] when a read made on this caller's behalf fails;
/// [`RpcFault::Store`] when the chain snapshot contradicts itself (more
/// burned than generated), for every caller, since every caller is told
/// what it contradicts.
pub fn daemon_status(
    facts: &dyn InfoFacts,
    chain_facts: &dyn ChainFacts,
    disclosure: Disclosure,
    rpc_connections: u64,
) -> Result<DaemonStatus, RpcFault> {
    let chain = facts.chain()?;
    let halt = chain_facts.chain_tip()?.halt;
    // The board's sessions, one snapshot: Health's `peered` and Status's two
    // counts. A node started offline binds no hub, so the board is not read;
    // every other hub that is not up is a fault.
    let sessions = if chain.offline {
        None
    } else {
        Some(facts.sessions()?)
    };
    // The pool. Every caller is told how many entries the node has made
    // public; how many it holds and has not is host-only. A retired pool
    // has no count: `null`, and the chain's members as ever.
    let pool = facts.pool_counts(if disclosure.host {
        PoolScope::WithUnbroadcast
    } else {
        PoolScope::Broadcast
    })?;
    let (txpool_count, txpool_retired, private) = match pool {
        PoolState::Live(counts) => (Some(Count(counts.broadcast)), false, counts.unbroadcast),
        PoolState::Retired => (None, true, None),
    };
    let txpool_private_count = match (disclosure.host, txpool_retired, private) {
        (true, false, Some(count)) => {
            Withheld::Shown(shekyl_rpc_types::Nullable(Some(Count(count))))
        }
        (true, true, _) => Withheld::Shown(shekyl_rpc_types::Nullable(None)),
        // Asked for on the host axis and not counted: not zero, a fault.
        (true, false, None) => return Err(RpcFault::Facts(FactsFault::Inconsistent)),
        (false, _, _) => Withheld::Withheld,
    };

    let status = if disclosure.status() {
        let status = facts.status()?;
        Some((status, facts.store_size()?))
    } else {
        None
    };

    // Whether P2P runs, and its two reads, come from the configuration
    // read in two places; if they disagree, one read is wrong, and the
    // reply refuses rather than carry both.
    let connector = if disclosure.peers() {
        match facts.peers()? {
            PeerFacts::Offline if chain.offline => Withheld::Shown(ConnectorMap::default()),
            PeerFacts::Running(map) if !chain.offline => Withheld::Shown(map),
            _ => {
                tracing::error!(
                    offline = chain.offline,
                    "daemon_status refused: the P2P state disagrees with the core's offline flag"
                );
                return Err(RpcFault::Facts(FactsFault::Inconsistent));
            }
        }
    } else {
        Withheld::Withheld
    };

    let count = chain.chain_height.to_raw();
    let tip = project_at_tip(
        &TipOperands {
            coins_generated: chain.already_generated_coins,
            total_burned: chain.total_burned,
            tx_volume: chain.tx_volume,
            chain_height: count,
        },
        shekyl_economics::economic_params(),
    );
    // More burned than generated is the store contradicting itself; a burn
    // of zero is a value, so it cannot stand for that.
    let burn = tip.burn_pct.map_err(|violation| {
        let fault = StoreFault::SupplyInvariant {
            coins_generated: violation.coins_generated,
            total_burned: violation.total_burned,
            chain_height: chain.chain_height,
        };
        tracing::error!("daemon_status refused: {fault}");
        RpcFault::Store(fault)
    })?;
    let on = disclosure.status();
    let status_count = |pick: fn(crate::info_facts::SessionCounts) -> u64| {
        shekyl_rpc_types::Nullable::from(sessions.map(|s| Count(pick(s))))
    };
    Ok(DaemonStatus {
        height: Height(
            chain
                .chain_height
                .tip()
                .map_or(0, shekyl_types::BlockHeight::to_raw),
        ),
        hash: HashHex::from_bytes(*chain.top_hash.as_bytes()),
        // The core's target as it reports it, `null` when it has none.
        target_height: chain
            .core_target_height
            .and_then(shekyl_types::ChainCount::tip)
            .map(|tip| Height(tip.to_raw()))
            .into(),
        synchronized: chain.synchronized,
        syncing: chain.busy_syncing,
        offline: chain.offline,
        degraded: chain.following_degraded,
        peered: sessions
            .map(crate::info_facts::SessionCounts::has_peers)
            .into(),
        writer: crate::reads::writer_of(halt),
        protocol_version: Integer(chain.protocol_version),
        difficulty: HexU128(chain.difficulty),
        difficulty_cumulative: HexU128(chain.cumulative_difficulty),
        block_spacing: Duration(chain.difficulty_target),
        // Coinbases excluded: one per block.
        tx_count: Count(chain.total_transactions.wrapping_sub(count)),
        block_weight_max: Size(chain.block_weight_limit),
        block_weight_median: Size(chain.block_weight_median),
        time_adjusted: Time(chain.adjusted_time),
        emission: AtomicUnitsString::from(tip.coins_generated),
        emission_multiplier: Micro(tip.release_multiplier),
        burn: Micro(burn),
        burn_total: AtomicUnitsString::from(tip.total_burned),
        stake_share: Micro(tip.staker_emission_share),
        txpool_count: txpool_count.into(),
        grant: disclosure.grants().iter().map(GrantName::from).collect(),
        started: shown(on, Time(status.as_ref().map_or(0, |(s, _)| s.start_time))),
        disk_free: shown(on, Size(status.as_ref().map_or(0, |(s, _)| s.free_space))),
        data_size: shown(on, Size(status.as_ref().map_or(0, |(_, size)| *size))),
        revision: shown(
            on,
            Text(
                status
                    .as_ref()
                    .map_or_else(String::new, |(s, _)| s.version.clone()),
            ),
        ),
        peer_outbound_count: shown(on, status_count(|s| s.outbound)),
        peer_inbound_count: shown(on, status_count(|s| s.inbound)),
        alt_count: shown(
            on,
            Count(status.as_ref().map_or(0, |(s, _)| s.alt_blocks_count)),
        ),
        rpc_connections: shown(on, Count(rpc_connections)),
        txpool_retired: shown(on, txpool_retired),
        connector,
        txpool_private_count,
    })
}

#[cfg(test)]
pub(crate) mod tests;
