// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! The RPC's value types for the p2p facts (net stats, the board's
//! connections, the peer lists) and the transaction bodies a store read
//! returns. Chain and pool reads go through the store, chain sync's view is
//! the node's (CS-5 §7), and the p2p facts are the node's
//! [`crate::chain_facts::P2pFacts`] over `shekyl-p2p`'s board: nothing
//! here reaches C++.

/// The body of one transaction as the store holds it: the **skeleton**
/// every node keeps at every horizon, and the **archival good** it may or
/// may not still hold (`PDM-Q6`; `SB-Q2`).
///
/// Not a wire type: which form the reply shows is the request's `prune`
/// switch (`methods::project_transactions`). The skeleton is enough for
/// the pruned form in every state. The full form is the recomposed body
/// when the good is held, the pruned segment alone when the record carries
/// no good, and `archived` where the good was discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    /// The pruned segment and the three txid operands.
    pub skeleton: shekyl_wire::SkeletonTx,
    /// The prunable region and the `pqc_auths` region, as one unit.
    pub good: ArchivalGood,
}

impl TxBody {
    /// The body in the full form (`PDM-Q10`). Held segments recompose in the
    /// order `shekyl_wire::TxSegments::concat` writes. A record that carries
    /// no good answers its pruned segment: that segment is the whole body.
    /// A discarded good answers `archived` with its shard. Every full-form
    /// projection goes through this one function.
    #[must_use]
    pub fn full_form(&self) -> FullForm {
        match &self.good {
            ArchivalGood::Retained {
                pqc_auths,
                prunable,
            } => FullForm::Whole(
                shekyl_wire::TxSegments {
                    pruned: self.skeleton.unprunable.clone(),
                    pqc_auths: pqc_auths.clone().unwrap_or_default(),
                    prunable: prunable.clone(),
                }
                .concat(),
            ),
            ArchivalGood::CarriesNone => FullForm::Whole(self.skeleton.unprunable.clone()),
            ArchivalGood::Discarded { shard } => FullForm::Archived { shard: *shard },
        }
    }
}

/// A body answered in the full form: its whole bytes, or the slot state
/// `archived` with the shard the archive serves it from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullForm {
    Whole(Vec<u8>),
    Archived { shard: shekyl_types::ShardId },
}

/// Whether this node holds a transaction's archival good, as the projection
/// sees it. The store records physical presence in two states; this enum
/// says what an absent segment means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchivalGood {
    /// Held: the `pqc_auths` segment (absent for a 3-part txid) and the
    /// prunable segment, as `Transaction::write_segments` wrote them. An
    /// empty prunable region that is still stored — a coinbase before the
    /// range delete — is this arm, and concatenates to the pruned segment.
    Retained {
        pqc_auths: Option<Vec<u8>>,
        prunable: Vec<u8>,
    },
    /// Discarded with its shard at the archival horizon (`PDM-Q9`). The
    /// record carries good, and the shard is where an archiver serves it.
    Discarded { shard: shekyl_types::ShardId },
    /// The record carries no archival good. The pruned segment is the whole
    /// body: a coinbase, including after the range delete removes its empty
    /// `txs_prunable` row. Not an empty [`Self::Retained`], and not
    /// [`Self::Discarded`].
    CarriesNone,
}

/// One request slot's answer, read from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxSlot {
    /// Neither the chain nor the pool had it.
    Missed,
    /// Not in the chain, and the pool is retired: whether the pool holds it
    /// has no answer. Only the Rust store backend retires its pool.
    PoolUnavailable,
    /// Found in a block.
    Chain {
        body: TxBody,
        block_height: u64,
        block_timestamp: u64,
        output_indices: Vec<u64>,
    },
    /// Found in the mempool. A pool entry's good is always held — nothing
    /// below the horizon is in the pool — so its [`TxBody::good`] is
    /// `Retained`.
    Pool {
        body: TxBody,
        double_spend_seen: bool,
        relayed: bool,
        /// `None` where the pool keeps no receive time (the Rust pool, S7).
        received_timestamp: Option<u64>,
    },
}

/// One live p2p connection, as the node read it from the session board.
///
/// Raw and absolute: the wire's elapsed times and rates are derived from
/// these against the one `now` beside the list, so a connection's reported
/// lifetime and the divisor behind its averages come from the same second.
// No `Eq`: the raw speeds are `f64`, and they are raw on purpose.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionFacts {
    /// `network_address::str()`: "host:port" for ipv4, the onion for tor.
    pub address: String,
    /// `network_address::host_str()`: the host alone.
    pub host: String,
    pub connection_id: [u8; 16],
    /// Unix seconds.
    pub started: u64,
    pub last_recv: u64,
    pub last_send: u64,
    /// Bytes, absolute.
    pub recv_count: u64,
    pub send_count: u64,
    /// Bytes/s, raw. Not yet an integer: `static_cast<uint64_t>` of a rate
    /// estimator's output is undefined for a NaN, an infinity, a negative or
    /// an out-of-range value, so the truncation happens here, clamped.
    pub current_speed_down: f64,
    pub current_speed_up: f64,
    pub port: u16,
    /// epee type id: 1 ipv4, 2 ipv6, 4 tor, …
    pub address_type: u8,
    pub incoming: bool,
    pub localhost: bool,
    pub local_ip: bool,
}

/// The live connections plus the single instant they were read at.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionsSnapshot {
    /// Unix seconds; one clock read for the whole list.
    pub now: u64,
    pub connections: Vec<ConnectionFacts>,
}

/// A P2P read from a daemon that may have been started offline
/// (Rick, 2026-10-14). [`P2pRead::Offline`] carries nothing: the daemon has no
/// peers, connections or lists by configuration, and nothing stands in for
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pRead<T> {
    /// P2P runs; what was read.
    Running(T),
    /// The daemon was started offline.
    Offline,
}

/// One peer-list entry, as the node read it. No clock: the lists carry
/// none (3.55). Named apart from
/// [`crate::info_facts::PeerFacts`], `get_info`'s Peers state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Already resolved per address arm by the adapter.
    pub host: String,
    /// The ipv4 address packed as `epee`'s `ipv4_network_address::ip()`
    /// returns it: the four octets in **network** order. On a little-endian
    /// host that means 10.32.0.7 is `0x0700_200a`, which is the value in the
    /// oracle vector beside the host string it renders to. Zero for every
    /// non-ipv4 arm.
    pub ip: u32,
    /// 0 for the address arms that carry none.
    pub port: u16,
    /// Which list it came from.
    pub white: bool,
    /// Whether the host is currently blocked; applying `include_blocked` is
    /// this side's job.
    pub blocked: bool,
}
