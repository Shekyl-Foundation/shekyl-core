// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What every method shares: the fault a handler returns and its class
//! (RW-Q3), the dotted diagnostic codes (`INPUT_GRAMMAR.md` IG-Q86), the
//! resource bounds (`RPC_CHANNEL.md` §6.3, IG-Q79), and the network's reads.
//!
//! Each function is the whole method: facts in, its reply type from
//! `shekyl_rpc_types::wire` out. The chain's reads are [`crate::reads`].

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::kinds::{Count, Duration, Endpoint, Height, Rate, Size, Text, Time};
use shekyl_rpc_types::wire::p2p;
use shekyl_types::ChainCount;
use shekyl_units::AtomicUnits;

use crate::chain_facts::{ChainFacts, FactsFault, P2pFacts};
use crate::core::P2pRead;
use crate::sync_facts::{RequestTiming, SyncSessionFacts, SyncViewRead};

/// The dotted diagnostic codes this daemon's methods refuse with
/// (IG-Q86): the first segment names what refused, the rest the fact.
pub mod codes {
    /// No block at that height or with that hash.
    pub const BLOCK_MISSING: &str = "block.missing";
    /// A range whose start is past its end.
    pub const BLOCK_RANGE: &str = "block.range";
    /// The node is not synchronized, so it has no tip to report.
    pub const CHAIN_SYNCING: &str = "chain.syncing";
    /// The chain advanced on every attempt to read its tip.
    pub const CHAIN_MOVING: &str = "chain.moving";
    /// The store contradicted itself.
    pub const CHAIN_INCONSISTENT: &str = "chain.inconsistent";
    /// The store's data file could not be read.
    pub const CHAIN_UNREADABLE: &str = "chain.unreadable";
    /// The store's supply figures contradict each other.
    pub const CHAIN_SUPPLY_INVARIANT: &str = "chain.supply-invariant";
    /// The handle behind the read is not supplied yet, or was taken down.
    pub const DAEMON_UNREADY: &str = "daemon.unready";
    /// A defect in the node; the parameter `stage` says where.
    pub const DAEMON_INTERNAL: &str = "daemon.internal";
    /// No transaction with that id on the chain or in the pool the caller
    /// may see.
    pub const TX_MISSING: &str = "tx.missing";
    /// The pool's file faulted; there is no pool until a restart.
    pub const TXPOOL_RETIRED: &str = "txpool.retired";
    /// No curve tree at that height.
    pub const CURVE_MISSING: &str = "curve.missing";
    /// A seed this node does not hold, or one above the tip.
    pub const POW_SEED: &str = "pow.seed";
    /// P2P is off: a read about peers has nothing to describe (IG-Q85).
    pub const P2P_OFFLINE: &str = "p2p.offline";
    /// Blocks one call may name (1,000).
    pub const BOUND_BLOCK: &str = "bound.block";
    /// Headers one range may span (1,000).
    pub const BOUND_HEADER: &str = "bound.header";
    /// Transactions one call may name (100).
    pub const BOUND_TX: &str = "bound.tx";
    /// Key images one call may name (5,000).
    pub const BOUND_KEY_IMAGE: &str = "bound.key-image";
    /// The size of `pow`'s hashing bytes.
    pub const BOUND_POW_SIZE: &str = "bound.pow-size";
    /// The shared hash budget cannot pay one hash.
    pub const BOUND_HASH: &str = "bound.hash";
}

/// Why a method could not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcFault {
    /// The facts source refused.
    Facts(FactsFault),
    /// The store's figures contradict each other, with the operands.
    Store(StoreFault),
    /// The method answered and the transport could not deliver it.
    Internal(InternalFault),
    /// The method refused: its class and its diagnostic.
    Refused(RpcError),
}

impl RpcFault {
    /// The error object this fault is on the wire (RW-Q3): its class and its
    /// dotted diagnostic. A fault the node caused carries no request detail.
    #[must_use]
    pub fn into_error(self) -> RpcError {
        let error =
            |class, code: &str, message: &str| RpcError::new(class, Diagnostic::new(code, message));
        match self {
            Self::Refused(error) => error,
            Self::Facts(FactsFault::NotReady) => error(
                ErrorClass::NotReady,
                codes::DAEMON_UNREADY,
                "this node's handle for the read is not ready",
            ),
            Self::Facts(FactsFault::Internal) => error(
                ErrorClass::Internal,
                codes::DAEMON_INTERNAL,
                "a read failed inside the node",
            )
            .with_param("stage", "read"),
            Self::Facts(FactsFault::Inconsistent) => error(
                ErrorClass::StoreFault,
                codes::CHAIN_INCONSISTENT,
                "this node's chain store contradicts itself",
            ),
            Self::Facts(FactsFault::StoreUnreadable) => error(
                ErrorClass::StoreFault,
                codes::CHAIN_UNREADABLE,
                "this node's chain store could not be read",
            ),
            Self::Store(store) => {
                let StoreFault::SupplyInvariant {
                    coins_generated,
                    total_burned,
                    chain_height,
                } = store;
                RpcError::new(
                    ErrorClass::StoreFault,
                    Diagnostic::new(codes::CHAIN_SUPPLY_INVARIANT, store.to_string())
                        .param("coins_generated", coins_generated.to_raw().to_string())
                        .param("total_burned", total_burned.to_raw().to_string())
                        .param("chain_height", chain_height.to_raw().to_string()),
                )
            }
            Self::Internal(stage) => error(
                ErrorClass::Internal,
                codes::DAEMON_INTERNAL,
                "the reply could not be delivered",
            )
            .with_param(
                "stage",
                match stage {
                    InternalFault::Serialize => "serialize",
                    InternalFault::Join => "join",
                },
            ),
        }
    }
}

/// A builder step on [`RpcError`]'s diagnostic.
trait WithParam {
    fn with_param(self, key: &str, value: &str) -> Self;
}

impl WithParam for RpcError {
    fn with_param(mut self, key: &str, value: &str) -> Self {
        self.diagnostic = self.diagnostic.param(key, value);
        self
    }
}

impl From<FactsFault> for RpcFault {
    fn from(fault: FactsFault) -> Self {
        Self::Facts(fault)
    }
}

impl From<FactsFault> for RpcError {
    fn from(fault: FactsFault) -> Self {
        RpcFault::Facts(fault).into_error()
    }
}

impl From<RpcError> for RpcFault {
    fn from(error: RpcError) -> Self {
        Self::Refused(error)
    }
}

/// The chain store's own figures contradict each other, found on this side
/// of the facts seam and reported with its operands.
///
/// **Verbose on purpose** (RK-Q9). A contradiction has a plausible-looking
/// fallback, a burn of zero, and a fallback reaches the caller as a fact.
/// So the method refuses, and says which invariant broke with what numbers.
/// Every operand is a public chain fact a successful reply would carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFault {
    /// More has been burned than was ever generated.
    SupplyInvariant {
        /// Gross coins emitted through the tip, in atomic units.
        coins_generated: AtomicUnits,
        /// Cumulative coins destroyed through the tip, in atomic units.
        total_burned: AtomicUnits,
        /// The snapshot's chain count: the top block's height plus one.
        chain_height: ChainCount,
    },
}

impl std::fmt::Display for StoreFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SupplyInvariant {
                coins_generated,
                total_burned,
                chain_height,
            } => write!(
                f,
                "the chain store contradicts itself: supply invariant violated \
                 (total_burned <= coins_generated). total_burned is {} atomic units and \
                 coins_generated is {} atomic units, at chain height {} (the top block's \
                 height plus one). Every burned unit was first emitted, so no burn \
                 can be computed from this store.",
                total_burned.to_raw(),
                coins_generated.to_raw(),
                chain_height.to_raw(),
            ),
        }
    }
}

impl std::error::Error for StoreFault {}

/// A failure on the transport's side of a method, never a fact about the
/// chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalFault {
    /// `serde_json` could not encode the reply.
    Serialize,
    /// The blocking task that ran the handler did not complete.
    Join,
}

/// A bounded connection asked for more than one request may
/// (`RPC_CHANNEL.md` §6.3): `OverResourceBound` with the bound's own code
/// (IG-Q79), its limit and what was asked. The method is not a parameter:
/// the caller knows what it called.
#[must_use]
pub fn bound_exceeded(code: &str, unit: &str, bound: u64, asked: u64) -> RpcFault {
    RpcFault::Refused(RpcError::new(
        ErrorClass::OverResourceBound,
        Diagnostic::new(
            code,
            format!(
                "a bounded connection may ask for at most {bound} {unit}; this asked for {asked}"
            ),
        )
        .param("bound", bound.to_string())
        .param("asked", asked.to_string()),
    ))
}

/// How many blocks a bounded connection may name in one call (inherited,
/// §6.3).
pub const RESTRICTED_BLOCK_COUNT: usize = 1000;
/// How many headers one range may span for a bounded connection.
pub const RESTRICTED_BLOCK_HEADER_RANGE: u64 = 1000;
/// How many transactions a bounded connection may name in one call.
pub const RESTRICTED_TRANSACTIONS_COUNT: usize = 100;
/// How many key images a bounded connection may name in one call.
pub const RESTRICTED_SPENT_KEY_IMAGES_COUNT: usize = 5000;

/// The refusal a read about peers earns from a daemon started offline: it
/// has nothing to describe by configuration (IG-Q85). `offline` on
/// `daemon_status` is the state as data.
#[must_use]
pub fn p2p_offline() -> RpcFault {
    RpcFault::Refused(RpcError::new(
        ErrorClass::RefusedByMethod,
        Diagnostic::new(
            codes::P2P_OFFLINE,
            "P2P is off on this node: it has no peers, connections or sync to describe",
        ),
    ))
}

/// `p2p_stats`: when P2P started, and what it has sent and received.
///
/// # Errors
///
/// The facts' fault.
pub fn p2p_stats(facts: &dyn P2pFacts) -> Result<p2p::P2pStats, RpcFault> {
    let stats = facts.net_stats()?;
    Ok(p2p::P2pStats {
        started: Time(stats.start_time),
        download: Size(stats.total_bytes_in),
        upload: Size(stats.total_bytes_out),
        download_packets: Count(stats.total_packets_in),
        upload_packets: Count(stats.total_packets_out),
    })
}

/// epee's Tor address-type id.
const ADDRESS_TYPE_TOR: u8 = 4;

/// Bytes per second, totally: a rate estimator's `f64` clamped to a `u64`,
/// zero for a NaN, an infinity or a negative.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the clamp above the cast is what makes it total"
)]
fn per_second(bytes_per_second: f64) -> Rate {
    /// 2^64 as an `f64`: one past `u64::MAX`.
    const OUT_OF_RANGE: f64 = 18_446_744_073_709_551_616.0;
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return Rate(0);
    }
    let whole = bytes_per_second.floor();
    Rate(if whole >= OUT_OF_RANGE {
        u64::MAX
    } else {
        whole as u64
    })
}

/// A claim's count as the tip it claims: `null` before any claim.
fn claimed_tip(count: Option<u64>) -> shekyl_rpc_types::Nullable<Height> {
    count
        .and_then(|count| count.checked_sub(1))
        .map(Height)
        .into()
}

/// One connection's facts on the wire, against the one instant the list
/// was read at, so no two elapsed values disagree. The subtractions
/// saturate: a clock that moved backwards answers zero.
fn connection(
    c: &crate::core::ConnectionFacts,
    now: u64,
    session: Option<&SyncSessionFacts>,
) -> p2p::Connection {
    let age = now.saturating_sub(c.started);
    p2p::Connection {
        inbound: c.incoming,
        local: c.localhost || c.local_ip,
        endpoint: Endpoint(c.address.clone()),
        connector: if c.address_type == ADDRESS_TYPE_TOR {
            p2p::Connector::Tor
        } else {
            p2p::Connector::Clearnet
        },
        download: Size(c.recv_count),
        upload: Size(c.send_count),
        // Floored at the connection's own age: a peer that has never sent
        // has been idle as long as it has been connected.
        download_idle: Duration(now.saturating_sub(c.started.max(c.last_recv))),
        upload_idle: Duration(now.saturating_sub(c.started.max(c.last_send))),
        mode: session.map(|session| session.mode).into(),
        age: Duration(age),
        download_speed_average: Rate(c.recv_count.checked_div(age).unwrap_or(0)),
        download_speed_current: per_second(c.current_speed_down),
        upload_speed_average: Rate(c.send_count.checked_div(age).unwrap_or(0)),
        upload_speed_current: per_second(c.current_speed_up),
        id: Text(hex::encode(c.connection_id)),
        height: claimed_tip(session.and_then(|session| session.claimed_height)),
    }
}

/// `peer_connections`: the live P2P connections.
///
/// # Errors
///
/// `p2p.offline` on a daemon started offline (IG-Q85); the facts' fault.
pub fn peer_connections(
    facts: &dyn P2pFacts,
    view: &dyn SyncViewRead,
) -> Result<Vec<p2p::Connection>, RpcFault> {
    if facts.p2p_state()? == P2pRead::Offline {
        return Err(p2p_offline());
    }
    let snapshot = facts.connections()?;
    let view = view.sync_view()?;
    Ok(snapshot
        .connections
        .iter()
        .map(|c| connection(c, snapshot.now, view.session(&c.connection_id)))
        .collect())
}

/// A host and a port as one endpoint; an IPv6 host takes brackets.
fn endpoint(host: &str, port: u16) -> Endpoint {
    if host.contains(':') {
        Endpoint(format!("[{host}]:{port}"))
    } else {
        Endpoint(format!("{host}:{port}"))
    }
}

/// `peer_list`: one list of known peers, each naming its tier (IG-Q51).
/// Endpoints not dialable on the public internet are included only when
/// asked for (`local`). A banned host is `ban_list`'s, not this list's.
///
/// # Errors
///
/// `p2p.offline` on a daemon started offline (IG-Q85); the facts' fault.
pub fn peer_list(
    facts: &dyn P2pFacts,
    request: &p2p::PeerListQuery,
) -> Result<Vec<p2p::PeerEntry>, RpcFault> {
    let entries = match facts.peer_list(!request.local)? {
        P2pRead::Offline => return Err(p2p_offline()),
        P2pRead::Running(entries) => entries,
    };
    Ok(entries
        .into_iter()
        .filter(|entry| !entry.blocked)
        .map(|entry| p2p::PeerEntry {
            endpoint: endpoint(&entry.host, entry.port),
            tier: if entry.white {
                p2p::Tier::White
            } else {
                p2p::Tier::Gray
            },
        })
        .collect())
}

/// `relay_stats` (host-only, RT-O9.3): the relay's floor and stem tallies.
///
/// # Errors
///
/// The facts' fault.
pub fn relay_stats(facts: &dyn P2pFacts) -> Result<p2p::RelayStats, RpcFault> {
    Ok(facts.stem_tallies()?)
}

/// A request in flight, in whole seconds: its age rounds down and its time
/// left rounds up, so `due` is `0` exactly when the response is late
/// (IG-Q80).
fn timing(timing: &RequestTiming) -> (Duration, Duration) {
    (
        Duration(timing.age_ms / 1000),
        Duration(timing.due_in_ms.div_ceil(1000)),
    )
}

/// `sync_status`: chain sync's view — toward what, from whom and how fast,
/// and whether it is stuck (IG-Q80).
///
/// Three reads: the tip, sync's view, and the board for each session's
/// endpoint. A session the view lists and the board no longer holds has
/// closed since, and is left out.
///
/// # Errors
///
/// `p2p.offline` on a daemon started offline (IG-Q85); the facts' fault.
pub fn sync_status(
    chain: &dyn ChainFacts,
    view: &dyn SyncViewRead,
    p2p_facts: &dyn P2pFacts,
) -> Result<p2p::SyncStatus, RpcFault> {
    if p2p_facts.p2p_state()? == P2pRead::Offline {
        return Err(p2p_offline());
    }
    let tip = chain.chain_tip()?;
    let view = view.sync_view()?;
    let board = p2p_facts.connections()?;
    let session = view
        .sessions
        .iter()
        .filter_map(|session| {
            let row = board
                .connections
                .iter()
                .find(|c| c.connection_id == session.connection_id)?;
            Some(p2p::Session {
                connection: Text(hex::encode(session.connection_id)),
                endpoint: Endpoint(row.address.clone()),
                height: claimed_tip(session.claimed_height),
                mode: session.mode,
                header: session
                    .header_request
                    .map(|request| {
                        let (age, due) = timing(&request);
                        p2p::HeaderRead { age, due }
                    })
                    .into(),
                span: session
                    .body_requests
                    .iter()
                    .map(|span| {
                        let (age, due) = timing(&span.timing);
                        p2p::BodySpan {
                            from: Height(span.start_height),
                            blocks: Count(span.count),
                            size: Size(span.planned_bytes),
                            age,
                            due,
                        }
                    })
                    .collect(),
                download_speed: session.rate.map(Rate).into(),
            })
        })
        .collect();
    let height = tip
        .chain_height
        .tip()
        .map_or(0, shekyl_types::BlockHeight::to_raw);
    Ok(p2p::SyncStatus {
        height: Height(height),
        target_height: Height(view.target.saturating_sub(1)),
        state: view.state,
        stalled: view.stalled,
        session,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chain_facts::{
        decode_target_count, BlockAt, BlockFacts, BlockHashAt, BlockHeaderAt, BlockHeaderFacts,
        ChainTip, DaemonIdentity, FeeEstimate, NetStats,
    };
    use crate::core::{ArchivalGood, ConnectionsSnapshot, TxBody};
    use crate::sync_facts::{BodySpanFacts, RequestTiming, SyncSessionFacts, SyncViewFacts};
    use serde_json::json;
    use shekyl_rpc_types::Nullable;
    use shekyl_rpc_types::{ChainSyncState, SyncMode};
    use shekyl_types::{
        AttestationRoot, BlockCount, BlockHash, BlockHeight, ChainCount, CurveTreeRoot, TxHash,
    };
    use shekyl_wire::Transaction;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// In-memory facts: what a store-backed implementation will look like.
    ///
    /// `block_hash_at` applies the **same bound the C++ shim does** rather
    /// than answering a constant, and records the height it was asked for.
    /// A double that ignored the height would be blind on the axis these
    /// tests are about: a handler forwarding `0`, or its own tip, instead of
    /// the caller's height would pass every one of them.
    pub(crate) struct FakeFacts {
        pub tip: Result<ChainTip, FactsFault>,
        /// Length of the fake chain for `block_hash_at`'s bound.
        pub hash_chain_height: ChainCount,
        /// When set, `block_hash_at` faults instead of answering.
        pub hash_fault: Option<FactsFault>,
        /// The last height `block_hash_at` was asked for.
        pub asked_height: AtomicU64,
        /// The header the fake chain holds at every in-range height.
        pub header: BlockHeaderFacts,
        /// When set, the hash arm answers an **alt** block declaring this
        /// height — the state only a hash lookup can reach, and the one the
        /// height arm's bound makes unrepresentable.
        pub alt_declared_height: Option<BlockHeight>,
        /// The last `fill_pow_hash` `block_header_at` was asked for.
        pub asked_pow: AtomicBool,
        /// The hash `block_at` was asked for, when it was asked by hash.
        pub asked_hash: std::sync::Mutex<Option<[u8; 32]>>,
        /// When set, `block_at` faults instead of answering.
        pub block_fault: Option<FactsFault>,
        /// How many times `block_header_at` was called.
        ///
        /// A *count*, not a last-value, because the property
        /// `get_block_headers_range` owes is about work not done: a range
        /// past the tip must be refused before any per-height read. An
        /// assertion on the error code alone cannot tell an O(1) refusal
        /// from one that walked the chain first and refused at the end.
        pub header_reads: AtomicU64,
        /// How many more header reads see the chain grow by one block first.
        ///
        /// **The input a fixed-height double cannot express.** `get_last_block_header`
        /// picks a height from one lock acquisition and projects it under
        /// another, so its defect only exists while the chain moves *between*
        /// them — a double whose height is constant makes that state
        /// unrepresentable and the retry unreachable. Counts down, so a test
        /// can say "move once, then settle" and assert convergence rather
        /// than just refusal.
        pub tip_growth_remaining: AtomicU64,
        /// Blocks the fake chain has grown so far, added to `hash_chain_height`.
        pub tip_grown: AtomicU64,
        /// The identity facts, or a fault. `None` means "the default
        /// mainnet identity", so the many tests that do not care about the
        /// tuple need not construct one.
        pub identity: Option<Result<DaemonIdentity, FactsFault>>,
    }

    impl FakeFacts {
        fn grown_chain(&self) -> ChainCount {
            self.hash_chain_height
                .saturating_add(BlockCount::from_raw(self.tip_grown.load(Ordering::Relaxed)))
        }
    }

    impl ChainFacts for FakeFacts {
        fn chain_tip(&self) -> Result<ChainTip, FactsFault> {
            self.tip.clone()
        }
        fn identity(&self) -> Result<DaemonIdentity, FactsFault> {
            self.identity.clone().unwrap_or_else(|| {
                Ok(DaemonIdentity {
                    nettype: shekyl_rpc_types::Network::Mainnet,
                    genesis_hash: shekyl_types::BlockHash::from_bytes([0x11; 32]),
                })
            })
        }

        fn fee_estimate(&self) -> Result<FeeEstimate, FactsFault> {
            Ok(FeeEstimate { fees: [10, 20, 40] })
        }

        fn block_hash_at(&self, height: BlockHeight) -> Result<BlockHashAt, FactsFault> {
            self.asked_height.store(height.to_raw(), Ordering::Relaxed);
            if let Some(fault) = self.hash_fault {
                return Err(fault);
            }
            Ok(BlockHashAt {
                hash: self
                    .hash_chain_height
                    .has_block(height)
                    .then(patterned_hash),
                chain_height: self.hash_chain_height,
            })
        }

        fn block_at(&self, at: BlockLookup, fill_pow_hash: bool) -> Result<BlockAt, FactsFault> {
            self.asked_pow.store(fill_pow_hash, Ordering::Relaxed);
            if let Some(fault) = self.block_fault {
                return Err(fault);
            }
            let chain_height = self.grown_chain();
            // The fake applies the same bound the shim does, so a handler that
            // forgets to check one cannot pass by luck.
            let present = match at {
                BlockLookup::Hash(hash) => {
                    *self.asked_hash.lock().expect("not poisoned") = Some(hash);
                    // Only the fake chain's one known hash resolves.
                    hash == patterned_hash().to_bytes()
                }
                BlockLookup::Height(height) => {
                    self.asked_height.store(height.to_raw(), Ordering::Relaxed);
                    self.hash_chain_height.has_block(height)
                }
            };
            if !present {
                return Ok(BlockAt {
                    block: None,
                    chain_height,
                });
            }
            let mut header = self.header.clone();
            header.pow_hash = fill_pow_hash.then(|| tagged_bytes(23));
            Ok(BlockAt {
                block: Some(BlockFacts {
                    header,
                    blob: vec![0x01, 0x02, 0xab, 0xff],
                    json: Some("{\n  \"major_version\": 1\n}".to_owned()),
                    tx_hashes: vec![
                        TxHash::from_bytes(tagged_bytes(61)),
                        TxHash::from_bytes(tagged_bytes(67)),
                    ],
                }),
                chain_height,
            })
        }

        fn block_header_at(
            &self,
            at: BlockLookup,
            fill_pow_hash: bool,
        ) -> Result<BlockHeaderAt, FactsFault> {
            self.header_reads.fetch_add(1, Ordering::Relaxed);
            // The chain grows *before* this read resolves its bound, which is
            // the ordering the race has: the caller chose a height from an
            // older snapshot, and this read sees a newer one.
            if self.tip_growth_remaining.load(Ordering::Relaxed) > 0 {
                self.tip_growth_remaining.fetch_sub(1, Ordering::Relaxed);
                self.tip_grown.fetch_add(1, Ordering::Relaxed);
            }
            self.asked_pow.store(fill_pow_hash, Ordering::Relaxed);
            if let Some(fault) = self.hash_fault {
                return Err(fault);
            }
            let chain_height = self.grown_chain();
            // Same two-arm shape as `block_at`, because it answers the same
            // question. **This is a fake chain's own shape, not a copy of the
            // shim's rule** — the fake chain has a height and nothing above it,
            // which is true of any chain. It is deliberately not described as
            // "the bound the shim applies": a double that claims to mirror a
            // rule has to be kept in sync to mean anything, and what the
            // handler actually owes is asserted directly from `asked_height` /
            // `asked_hash` instead.
            let height = match at {
                BlockLookup::Hash(hash) => {
                    *self.asked_hash.lock().expect("not poisoned") = Some(hash);
                    if hash != patterned_hash().to_bytes() {
                        return Ok(BlockHeaderAt {
                            header: None,
                            chain_height,
                        });
                    }
                    // A hash reaches blocks off the main chain, so the height
                    // is the block's own and can sit anywhere — including at
                    // or past the tip, which is the input the height arm
                    // cannot express and the widening made reachable.
                    self.alt_declared_height.unwrap_or(self.header.height)
                }
                BlockLookup::Height(height) => {
                    self.asked_height.store(height.to_raw(), Ordering::Relaxed);
                    if !chain_height.has_block(height) {
                        return Ok(BlockHeaderAt {
                            header: None,
                            chain_height,
                        });
                    }
                    height
                }
            };
            let mut h = self.header.clone();
            h.height = height;
            // **Depth is derived, not canned.** "How far below the tip" is
            // what depth *means* — a property of a chain, not a rule the shim
            // chose — so a fake chain that reports one inconsistent with its
            // own height is simply wrong, and a test about the tip could not
            // observe it. (This is not the mirroring a double must avoid: the
            // fake is not restating a C++ policy, it is being a chain.) One
            // test used to compensate by hand, setting `hash_chain_height` to
            // `1_234_567 + 42 + 1` so the canned depth would line up.
            h.depth = chain_height
                .tip()
                .map(|top| top.saturating_sub(height))
                .unwrap_or(BlockCount::from_raw(0));
            h.pow_hash = fill_pow_hash.then(|| tagged_bytes(23));
            // Only the alt case overrides it. `sample_header()` carries the
            // value the RK-3 oracle vector was captured with, and clobbering
            // that on the height arm made this fake disagree with the vector
            // it exists to reproduce.
            if self.alt_declared_height.is_some() && matches!(at, BlockLookup::Hash(_)) {
                h.orphan_status = true;
            }
            Ok(BlockHeaderAt {
                header: Some(h),
                chain_height,
            })
        }
    }

    pub(crate) fn patterned_hash() -> BlockHash {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = u8::try_from((i * 7 + 3) & 0xff).expect("masked to one byte");
        }
        BlockHash::from_bytes(b)
    }

    pub(crate) fn facts(synchronized: bool, target: u64) -> FakeFacts {
        FakeFacts {
            tip: Ok(ChainTip {
                chain_height: ChainCount::from_raw(1_234_567),
                top_hash: patterned_hash(),
                target_height: decode_target_count(target),
                synchronized,
                release_build: false,
            }),
            hash_chain_height: ChainCount::from_raw(1_234_567),
            hash_fault: None,
            asked_height: AtomicU64::new(u64::MAX),
            header_reads: AtomicU64::new(0),
            tip_growth_remaining: AtomicU64::new(0),
            tip_grown: AtomicU64::new(0),
            identity: None,
            header: sample_header(),
            alt_declared_height: None,
            asked_pow: AtomicBool::new(false),
            asked_hash: std::sync::Mutex::new(None),
            block_fault: None,
        }
    }

    /// The fixed facts the RK-3 oracle vector was captured from.
    pub(crate) fn sample_header() -> BlockHeaderFacts {
        BlockHeaderFacts {
            hash: tagged_hash(11),
            prev_hash: tagged_hash(3),
            miner_tx_hash: TxHash::from_bytes(tagged_bytes(31)),
            curve_tree_root: CurveTreeRoot::from_bytes(tagged_bytes(41)),
            attestation_root: AttestationRoot::from_bytes(tagged_bytes(53)),
            pow_hash: None,
            height: BlockHeight::from_raw(1_234_567),
            depth: BlockCount::from_raw(42),
            timestamp: 1_700_000_000,
            difficulty: (1u128 << 70) + 12345,
            cumulative_difficulty: (1u128 << 71) + 99,
            reward: 600_000_000_000,
            block_weight: 98765,
            long_term_weight: Some(87654),
            num_txes: 7,
            nonce: 305_419_896,
            major_version: 1,
            minor_version: 2,
            orphan_status: true,
        }
    }

    /// The emitter's `tagged_hash`: byte i = (i*7 + tag) & 0xff.
    /// The oracle emitter's pattern: byte i = (i*7 + tag) & 0xff. Raw bytes,
    /// so each call site names the kind of hash it is building.
    pub(crate) fn tagged_bytes(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, byte) in b.iter_mut().enumerate() {
            let i = u8::try_from(i).expect("32 fits u8");
            *byte = i.wrapping_mul(7).wrapping_add(tag);
        }
        b
    }

    pub(crate) fn tagged_hash(tag: u8) -> BlockHash {
        BlockHash::from_bytes(tagged_bytes(tag))
    }

    /// The same fixed facts the oracle vectors were captured from produce the
    /// same document — the end-to-end form of the `shekyl-rpc-types` parity
    /// test, through the handler.
    #[test]
    fn get_height_reproduces_the_oracle_vector() {
        let out = get_height(&facts(true, 0)).unwrap();
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_height_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
    }

    // ── the get_transactions projection ─────────────────────────────────

    /// A real transaction as the store hands it over: its skeleton and its
    /// archival good, cut by the wire crate's own segmenter and bound by
    /// its own `txid_parts`.
    fn stored(full: &[u8]) -> TxBody {
        let tx = Transaction::from_bytes(full).expect("a real transaction");
        let segments = tx.write_segments().expect("segments");
        let parts = tx.txid_parts();
        TxBody {
            skeleton: shekyl_wire::SkeletonTx {
                unprunable: segments.pruned,
                prunable_hash: parts.prunable_hash,
                pqc_auth_hash: parts.pqc_auth_hash,
                archival_len: parts.archival_len,
            },
            good: ArchivalGood::Retained {
                pqc_auths: parts.pqc_auth_hash.map(|_| segments.pqc_auths),
                prunable: segments.prunable,
            },
        }
    }

    /// The pinned parity spend (`shekyl-wire`'s `pruned_tx_hash_parity_v1`),
    /// with the archival length the fixture pins for it.
    fn stored_spend() -> (TxBody, u64) {
        let pin: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
        ))
        .expect("parity fixture");
        let full = hex::decode(pin["tx_hex"].as_str().expect("tx_hex")).expect("hex");
        (
            stored(&full),
            pin["archival_len"].as_u64().expect("archival_len"),
        )
    }

    /// A real coinbase: no `pqc_auths`, an empty prunable region, no
    /// archival good.
    fn stored_coinbase() -> TxBody {
        let block = shekyl_wire::Block::from_bytes(include_bytes!(
            "../../shekyl-wire/tests/vectors/regtest_coinbase_h1.block"
        ))
        .expect("block vector");
        stored(&block.miner_transaction.serialize())
    }

    fn chain_slot(body: TxBody) -> TxSlot {
        TxSlot::Chain {
            body,
            block_height: 7,
            block_timestamp: 1_700_000_000,
            output_indices: vec![3, 4],
        }
    }

    fn archived(body: &TxBody, shard: u64) -> TxBody {
        TxBody {
            skeleton: body.skeleton.clone(),
            good: ArchivalGood::Discarded {
                shard: shekyl_types::ShardId::from_raw(shard),
            },
        }
    }

    fn req(prune: bool) -> GetTransactionsRequest {
        GetTransactionsRequest {
            txs_hashes: vec![],
            prune,
        }
    }

    /// **The pruned form is the skeleton, and the full form is the whole
    /// body.** `pruned_as_hex` is the pruned segment alone — the `pqc_auths`
    /// region is archival good and is never appended to it — and the three
    /// operands are carried in both forms, identically: a wallet rebinds the
    /// txid from them (`SB-Q2`; `SHT-Q2`).
    #[test]
    fn the_pruned_form_is_the_skeleton_and_the_full_form_the_whole_body() {
        let (body, pinned_len) = stored_spend();
        let ArchivalGood::Retained {
            pqc_auths,
            prunable,
        } = &body.good
        else {
            unreachable!("the fixture is retained");
        };
        let pqc_auths = pqc_auths.as_ref().expect("the pinned spend is 4-part");
        assert!(!pqc_auths.is_empty() && !prunable.is_empty());
        let pruned_hex = hex::encode(&body.skeleton.unprunable);
        let full_hex = format!(
            "{pruned_hex}{}{}",
            hex::encode(pqc_auths),
            hex::encode(prunable)
        );

        let pruned =
            project_transactions(&req(true), &[[0x01; 32]], &[chain_slot(body.clone())], 9);
        let full = project_transactions(&req(false), &[[0x01; 32]], &[chain_slot(body.clone())], 9);
        let (p, f) = (&pruned.txs[0], &full.txs[0]);
        assert_eq!(p.pruned_as_hex, pruned_hex, "the pruned segment alone");
        assert!(p.as_hex.is_empty());
        assert_eq!(f.as_hex, full_hex, "pruned ‖ pqc_auths ‖ prunable");
        assert!(f.pruned_as_hex.is_empty());
        for (label, e) in [("prune", p), ("full", f)] {
            assert_eq!(e.archival_len, pinned_len, "archival_len @ {label}");
            assert_eq!(
                e.prunable_hash,
                HashHex::from_bytes(body.skeleton.prunable_hash.to_bytes()),
                "prunable_hash @ {label}"
            );
            assert_eq!(
                e.pqc_auth_hash.into_option(),
                body.skeleton
                    .pqc_auth_hash
                    .map(|hash| HashHex::from_bytes(hash.to_bytes())),
                "pqc_auth_hash @ {label}"
            );
        }
        assert!(pruned.archived.is_empty() && full.archived.is_empty());
    }

    /// **A discarded good answers `archived` in the full form, and the
    /// skeleton in the pruned form** (`PDM-Q10`). The id leaves `txs` for
    /// the side list with its shard; it is not a miss and not a failure. The
    /// skeleton served under `prune` is byte-identical before and after the
    /// discard: the pruned form never depended on the good.
    #[test]
    fn a_discarded_good_is_archived_in_the_full_form_and_a_skeleton_under_prune() {
        let (held, _) = stored_spend();
        let gone = archived(&held, 3);
        let id = [0x05; 32];

        let full = project_transactions(&req(false), &[id], &[chain_slot(gone.clone())], 9);
        assert!(full.txs.is_empty(), "an archived id is not an entry");
        assert!(full.missed_tx.is_empty(), "nor a miss");
        assert_eq!(
            full.archived,
            vec![ArchivedTx {
                tx_hash: HashHex::from_bytes(id),
                shard: 3,
            }]
        );

        let before = project_transactions(&req(true), &[id], &[chain_slot(held)], 9);
        let after = project_transactions(&req(true), &[id], &[chain_slot(gone)], 9);
        assert_eq!(before, after, "one shape under prune, whatever the good");
        assert!(after.archived.is_empty());
    }

    /// A coinbase has no archival good, so it is never `archived`: its
    /// whole body is its skeleton, its `pqc_auth_hash` is null and its
    /// length zero, in both forms.
    #[test]
    fn a_coinbase_answers_its_whole_body_in_both_forms() {
        let body = stored_coinbase();
        let pruned_hex = hex::encode(&body.skeleton.unprunable);
        let full = project_transactions(&req(false), &[[0x02; 32]], &[chain_slot(body.clone())], 9);
        let pruned = project_transactions(&req(true), &[[0x02; 32]], &[chain_slot(body)], 9);
        assert_eq!(full.txs[0].as_hex, pruned_hex);
        assert_eq!(pruned.txs[0].pruned_as_hex, pruned_hex);
        for e in [&full.txs[0], &pruned.txs[0]] {
            assert_eq!(e.pqc_auth_hash, shekyl_rpc_types::Nullable::NULL);
            assert_eq!(e.archival_len, 0);
        }
        assert!(full.archived.is_empty());
    }

    /// **No good is the pruned segment, not an empty retained region and
    /// not `archived`.** This is the coinbase after the range delete has
    /// removed its empty `txs_prunable` row: the store's physical state is
    /// absence, and the projection must not invent segments to stand in
    /// for a good the record does not carry (`SB-Q2`).
    #[test]
    fn a_body_that_carries_no_good_answers_its_pruned_segment() {
        let held = stored_coinbase();
        let body = TxBody {
            skeleton: held.skeleton,
            good: ArchivalGood::CarriesNone,
        };
        let pruned_hex = hex::encode(&body.skeleton.unprunable);
        let full = project_transactions(&req(false), &[[0x02; 32]], &[chain_slot(body.clone())], 9);
        let pruned = project_transactions(&req(true), &[[0x02; 32]], &[chain_slot(body)], 9);
        assert_eq!(full.txs[0].as_hex, pruned_hex);
        assert!(full.txs[0].pruned_as_hex.is_empty());
        assert_eq!(pruned.txs[0].pruned_as_hex, pruned_hex);
        assert!(full.archived.is_empty() && pruned.archived.is_empty());
    }

    /// Chain, pool, miss and an unavailable pool lookup land in their own
    /// places: the first two become entries carrying their location, the
    /// third only a `missed_tx` id, the fourth only an `unavailable_tx` id.
    #[test]
    fn chain_pool_and_missed_slots_are_projected_to_their_own_places() {
        let (body, pinned_len) = stored_spend();
        let out = project_transactions(
            &req(true),
            &[[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]],
            &[
                chain_slot(body.clone()),
                TxSlot::Pool {
                    body,
                    double_spend_seen: true,
                    relayed: true,
                    received_timestamp: Some(1_700_000_001),
                },
                TxSlot::Missed,
                TxSlot::PoolUnavailable,
            ],
            9,
        );

        assert_eq!(out.txs.len(), 2, "the miss must not become an entry");
        assert_eq!(out.missed_tx, vec![HashHex::from_bytes([0x03; 32])]);
        assert_eq!(
            out.unavailable_tx,
            vec![HashHex::from_bytes([0x04; 32])],
            "an unavailable lookup is neither an entry nor a miss"
        );
        assert!(matches!(out.txs[0].location, TxLocation::Mined { .. }));
        assert!(matches!(out.txs[1].location, TxLocation::Pooled { .. }));
        assert!(
            out.txs[1].double_spend_seen,
            "the pool's double-spend flag must survive the projection"
        );
        assert_eq!(
            out.txs[1].archival_len, pinned_len,
            "a pooled transaction's operands are the same as a mined one's"
        );
        assert_eq!(out.txs[0].pruned_as_hex, out.txs[1].pruned_as_hex);
    }

    #[test]
    fn get_version_reproduces_the_synced_oracle_vector() {
        // Synchronized with a non-zero raw target: the reply carries that
        // target. Synchronization is not encoded by writing 0 here.
        //
        // Against `_v5`: 3.28 removed the peer identifier from every readout
        // (PWD-I1). Before it: RK-5b's three header-method shape changes bumped
        // `CORE_RPC_VERSION` to 3.27 (3.26 was C2-R1b's `following_degraded`,
        // 3.25 the RK-4c removals), and the vectors are never hand-edited
        // (see their README), so each bump gets a file beside the C++ capture
        // rather than inside it. `the_get_version_chain_differs_by_exactly_
        // the_version_at_every_link` is what keeps the whole chain honest —
        // it replaced a test that pinned only the newest pair, which is
        // exactly what let this branch and `dev` both write 196634.
        // `_v6` adds the identity tuple (VC-2). Two of its three fields are
        // **moving values a captured vector must not chase**, for the same
        // reason `version` is: the digest moves whenever `config/` moves, and
        // the genesis hash is per network. A vector carrying either live value
        // would have to be re-minted on every constants edit. So the vector
        // holds obviously-synthetic fixtures, this test compares every other
        // field against it, and each moving field is asserted against its own
        // source — the digest against the compiled constant, the genesis and
        // nettype against what the facts layer handed up.
        let out = get_version(&facts(true, 999_999)).unwrap();
        assert_eq!(out.target_height, Nullable::value(999_999));
        assert_eq!(
            out.consensus_constants_digest,
            shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH,
            "the reply must carry this build's own digest, not a stored one"
        );
        assert_eq!(out.nettype, shekyl_rpc_types::Network::Mainnet);
        assert_eq!(
            out.genesis_hash,
            shekyl_rpc_types::HashHex::from_bytes([0x11; 32]),
            "the genesis hash must come from the facts layer, unaltered"
        );

        let mut ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        // Head of the `get_version` chain (`_v47` = 3.70). A bump that
        // forgets this include fails on `version` below.
        let mut oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_version_synced_v47.json"
        ))
        .unwrap();
        for moving in ["consensus_constants_digest", "genesis_hash"] {
            assert!(
                ours.as_object_mut().unwrap().remove(moving).is_some(),
                "{moving} must be present before it is excluded"
            );
            assert!(
                oracle.as_object_mut().unwrap().remove(moving).is_some(),
                "the vector must carry {moving}"
            );
        }
        assert_eq!(ours, oracle);
    }

    #[test]
    fn get_version_reports_the_target_while_syncing() {
        let out = get_version(&facts(false, 2_000_000)).unwrap();
        assert_eq!(out.target_height, Nullable::value(2_000_000));
        assert_eq!(out.version, shekyl_rpc_types::CORE_RPC_VERSION);
    }

    /// **No target is `null`, not `0` and not an omitted member** (RK-Q7),
    /// and a chain count of `0` is written as `0` (RK-D23). The facts layer
    /// reports "no target" as `None`; the reply writes that as `null`,
    /// whether or not the node is synchronized.
    #[test]
    fn get_version_writes_no_target_as_null_and_a_zero_height_as_zero() {
        for synchronized in [true, false] {
            let mut facts = facts(synchronized, 0);
            facts.tip.as_mut().expect("a tip").chain_height = ChainCount::from_raw(0);
            let out = get_version(&facts).unwrap();
            assert_eq!(out.target_height, Nullable::NULL);
            let wire = serde_json::to_value(&out).unwrap();
            assert_eq!(wire["target_height"], serde_json::Value::Null);
            assert_eq!(wire["current_height"], serde_json::json!(0));
        }
    }

    /// A facts fault is a fault, never a fabricated reply.
    #[test]
    fn facts_fault_is_not_answered_with_zeros() {
        let f = FakeFacts {
            tip: Err(FactsFault::NotReady),
            hash_chain_height: ChainCount::ZERO,
            hash_fault: Some(FactsFault::NotReady),
            asked_height: AtomicU64::new(u64::MAX),
            header_reads: AtomicU64::new(0),
            tip_growth_remaining: AtomicU64::new(0),
            tip_grown: AtomicU64::new(0),
            identity: None,
            header: sample_header(),
            alt_declared_height: None,
            asked_pow: AtomicBool::new(false),
            asked_hash: std::sync::Mutex::new(None),
            block_fault: None,
        };
        assert_eq!(get_height(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(get_version(&f), Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(
            get_block_count(&f),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
        assert_eq!(
            get_block_hash(&f, 1),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
    }

    /// The count is the chain height, and it reproduces the epee vector.
    #[test]
    fn get_block_count_reproduces_the_oracle_vector() {
        let out = get_block_count(&facts(true, 0)).unwrap();
        assert_eq!(out.count, 1_234_567);
        let ours: serde_json::Value = serde_json::to_value(&out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_block_count_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
    }

    /// The hash reply is a bare JSON string of 64 lowercase hex characters —
    /// the vector is that document, with no object around it and no `status`.
    #[test]
    fn get_block_hash_reproduces_the_oracle_vector() {
        let f = facts(true, 0);
        let out = get_block_hash(&f, 42).unwrap();
        assert_eq!(
            f.asked_height.load(Ordering::Relaxed),
            42,
            "the handler must ask facts for the height it was given"
        );
        let ours = serde_json::to_value(out).unwrap();
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../shekyl-rpc-types/tests/vectors/rpc/get_block_hash_v1.json"
        ))
        .unwrap();
        assert_eq!(ours, oracle);
        assert!(oracle.is_string(), "the reply is a bare JSON string");
    }

    /// A height at or past the tip is refused with the C++ code and message,
    /// naming the top height (chain height - 1).
    #[test]
    fn height_past_the_tip_is_refused_with_the_top_height_named() {
        let f = facts(true, 0);
        // The bound is the fake chain's, applied to the height asked for:
        // one below the tip answers, the tip itself does not.
        assert!(get_block_hash(&f, 1_234_566).is_ok());
        assert!(get_block_hash(&f, 1_234_567).is_err());
        let err = get_block_hash(&f, 9_000_000).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                message: "Requested block height: 9000000 greater than current top block \
                          height: 1234566"
                    .to_owned(),
                data: None,
            })
        );
    }

    /// A chain whose tip is 42 blocks above the header the oracle vector was
    /// captured at, so `depth` and the bound are both meaningful.
    ///
    /// Whether a pow hash comes back is not a property of the fixture: the
    /// fake computes one exactly when the handler asks for one, so the tests
    /// vary `get_block_header_by_height`'s own `fill_pow_hash` argument.
    fn header_facts() -> FakeFacts {
        let mut f = facts(true, 0);
        f.hash_chain_height = ChainCount::from_raw(1_234_610); // 1_234_567 + depth 42 + 1
        f
    }

    fn oracle(name: &str) -> serde_json::Value {
        let raw = match name {
            "full" => include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_block_header_by_height_full_v1.json"
            ),
            _ => include_str!(
                "../../shekyl-rpc-types/tests/vectors/rpc/get_block_header_by_height_defaults_v1.json"
            ),
        };
        serde_json::from_str(raw).expect("vector is JSON")
    }

    /// The whole header projection reproduces epee's document from the same
    /// fixed facts — every field, the 128-bit split, and the pow hash.
    #[test]
    fn header_reproduces_the_full_oracle_vector() {
        let f = header_facts();
        let out = get_block_header_by_height(&f, 1_234_567, true).unwrap();
        assert!(
            f.asked_pow.load(Ordering::Relaxed),
            "the handler must pass the caller's fill_pow_hash to facts"
        );
        assert_eq!(serde_json::to_value(&out).unwrap(), oracle("full"));
    }

    /// Without `fill_pow_hash` the wire carries an empty `pow_hash`, and the
    /// facts layer is never asked to compute one.
    #[test]
    fn pow_hash_is_empty_and_uncomputed_when_not_requested() {
        let f = header_facts();
        let out = get_block_header_by_height(&f, 1_234_567, false).unwrap();
        assert!(!f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(out.block_header.pow_hash, None);
    }

    /// Absent params keep epee's defaults; `{}` is height 0, as the live
    /// daemon answers. Refusing either of these turns this red.
    #[test]
    fn absent_params_are_the_defaults_not_a_refusal() {
        for absent in [json!(null), json!({})] {
            let request = block_header_request(&absent).expect("absent params are allowed");
            assert_eq!(request.height, 0, "{absent} must mean height 0");
            assert!(!request.fill_pow_hash);
        }
        let given = block_header_request(&json!({"height": 7, "fill_pow_hash": true}))
            .expect("well-formed params parse");
        assert_eq!(given.height, 7);
        assert!(given.fill_pow_hash);
    }

    /// Params that are present but unusable are refused rather than read as
    /// height 0 — epee answered every one of these with the genesis header.
    /// Restoring `unwrap_or_default()` turns this red.
    #[test]
    fn unusable_params_are_refused_not_read_as_genesis() {
        for bad in [
            json!({"height": "nope"}),
            json!({"height": -1}),
            json!({"height": 1.5}),
            // Height fine, the other field not: the refusal must not claim a
            // height was expected.
            json!({"height": 7, "fill_pow_hash": "yes"}),
            json!({"fill_pow_hash": "yes"}),
            // An array is `on_get_block_hash`'s shape, not this method's.
            json!([0]),
            json!([7, true]),
            json!("0"),
            json!(0),
            json!(true),
        ] {
            let refusal = block_header_request(&bad)
                .expect_err(&format!("{bad} is not a usable params value"));
            assert_eq!(
                refusal,
                RpcFault::Refused(RpcRefusal::wrong_param(WRONG_HEADER_PARAMS)),
                "{bad} must be refused, naming this method's own params shape"
            );
        }
    }

    /// The four RK-5b params parsers each accept absent params and their own
    /// object, and refuse every other shape — an array included.
    ///
    /// The array rows are the ones with a defect behind them: serde's derive
    /// reads a struct out of a sequence, so without the explicit arm
    /// `getblockheadersrange` would have quietly gained a positional form
    /// `[start, end]` that nothing designed and nothing else in the daemon
    /// accepts.
    #[test]
    fn the_rk5b_params_parsers_take_one_shape_each() {
        assert_eq!(
            last_block_header_request(&json!(null)).unwrap(),
            GetLastBlockHeaderRequest::default()
        );
        assert!(
            last_block_header_request(&json!({"fill_pow_hash": true}))
                .unwrap()
                .fill_pow_hash
        );

        let range = block_headers_range_request(&json!({"start_height": 3, "end_height": 9}))
            .expect("an object with both heights");
        assert_eq!((range.start_height, range.end_height), (3, 9));
        // **A range has no empty form, and both spellings of "nothing" say so
        // the same way.** The C++ answered for block 0 whether params were
        // absent or `{}`; the first port defaulted the first and refused the
        // second, so the two stopped meaning the same thing. Both are now
        // refused — a client that forgot its heights is told it forgot,
        // rather than told about genesis.
        for empty in [json!(null), json!({}), json!({"fill_pow_hash": true})] {
            assert!(
                block_headers_range_request(&empty).is_err(),
                "{empty} names no range and must be refused"
            );
        }

        assert!(
            fee_estimate_request(&json!({"grace_blocks": 5})).is_err(),
            "grace_blocks was deleted at 3.57 and is refused, not ignored"
        );
        assert_eq!(
            fee_estimate_request(&json!({})).unwrap(),
            GetFeeEstimateRequest::default()
        );
        assert_eq!(
            block_header_by_hash_request(&json!({"hashes": []}))
                .unwrap()
                .hashes
                .len(),
            0
        );

        // Every parser, every non-object shape. The refusal each carries is
        // its own wording, so this asserts the code and leaves the message to
        // the parser that owns it.
        for bad in [json!([0]), json!([3, 9]), json!("0"), json!(0), json!(true)] {
            for refusal in [
                last_block_header_request(&bad).err(),
                block_header_by_hash_request(&bad).err(),
                block_headers_range_request(&bad).err(),
                fee_estimate_request(&bad).err(),
            ] {
                let RpcFault::Refused(refusal) =
                    refusal.unwrap_or_else(|| panic!("{bad} is not a usable params value"))
                else {
                    panic!("{bad} must be refused as a bad request, not a facts fault");
                };
                assert_eq!(refusal.code, CORE_RPC_ERROR_CODE_WRONG_PARAM);
            }
        }

        // And a field of the wrong type inside a well-shaped object.
        assert!(block_headers_range_request(&json!({"start_height": -1})).is_err());
    }

    fn block_req(hash: &str, height: u64) -> GetBlockRequest {
        GetBlockRequest {
            hash: hash.to_owned(),
            height,
            fill_pow_hash: false,
        }
    }

    /// A whole block by height: the header, both copies of the miner tx
    /// hash, the hex blob, the json carried through, and the tx list.
    #[test]
    fn block_by_height_carries_every_part_of_the_reply() {
        let f = header_facts();
        let out = get_block(&f, &block_req("", 1_234_567), false).unwrap();
        assert!(out.status.is_ok());
        assert_eq!(out.block_header.height, 1_234_567);
        assert_eq!(
            out.miner_tx_hash, out.block_header.miner_tx_hash,
            "the wire carries the miner tx hash twice, and they must agree"
        );
        assert_eq!(
            out.blob, "0102abff",
            "the blob is lowercase hex of the bytes"
        );
        assert_eq!(out.json.as_deref(), Some("{\n  \"major_version\": 1\n}"));
        assert_eq!(out.tx_hashes.len(), 2);
        assert_eq!(out.tx_hashes[0], HashHex::from_bytes(tagged_bytes(61)));
    }

    /// A hash wins over a height, and the height is not consulted at all —
    /// passing a past-the-tip height alongside a good hash still answers.
    #[test]
    fn a_hash_wins_over_a_height() {
        let f = header_facts();
        let hash = patterned_hash().to_string();
        let out = get_block(&f, &block_req(&hash, 9_000_000), false).unwrap();
        assert!(out.status.is_ok());
        assert_eq!(
            *f.asked_hash.lock().unwrap(),
            Some(patterned_hash().to_bytes()),
            "the facts layer must be asked by hash, not by the ignored height"
        );
    }

    /// An unparseable hash keeps the C++ diagnostic, which quotes what the
    /// caller sent — the reason the request field is a `String` (RK-D12).
    #[test]
    fn an_unparseable_hash_quotes_what_was_sent() {
        let f = header_facts();
        let err = get_block(&f, &block_req("nonsense", 0), false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal::wrong_param(
                "Failed to parse hex representation of block hash. Hex = nonsense."
            ))
        );
    }

    /// Past the tip is the height refusal, naming the top height; a hash the
    /// chain does not have is the C++'s internal-error wording instead.
    #[test]
    fn absence_keeps_the_refusal_that_matches_the_lookup() {
        let f = header_facts();
        assert_eq!(
            get_block(&f, &block_req("", 9_000_000), false).unwrap_err(),
            too_big_height(BlockHeight::from_raw(9_000_000), f.hash_chain_height,)
        );

        let unknown = HashHex::from_bytes([9u8; 32]).to_string();
        assert_eq!(
            get_block(&f, &block_req(&unknown, 0), false).unwrap_err(),
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: format!("Internal error: can't get block by hash. Hash = {unknown}."),
                data: None,
            })
        );
    }

    /// A block whose coinbase is not a single `txin_gen` keeps the C++'s own
    /// message rather than becoming a generic internal error.
    #[test]
    fn a_malformed_coinbase_keeps_its_own_message() {
        let mut f = header_facts();
        f.block_fault = Some(FactsFault::Inconsistent);
        assert_eq!(
            get_block(&f, &block_req("", 0), false).unwrap_err(),
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: "Internal error: coinbase transaction in the block has the wrong type"
                    .to_owned(),
                data: None,
            })
        );
    }

    /// The pow hash is asked for only when the caller asked and was allowed.
    #[test]
    fn block_pow_hash_follows_the_entitlement() {
        let f = header_facts();
        let plain = get_block(&f, &block_req("", 1_234_567), false).unwrap();
        assert!(!f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(plain.block_header.pow_hash, None);

        let filled = get_block(&f, &block_req("", 1_234_567), true).unwrap();
        assert!(f.asked_pow.load(Ordering::Relaxed));
        assert_eq!(
            filled.block_header.pow_hash,
            Some(HashHex::from_bytes(tagged_bytes(23)))
        );
    }

    /// This method's params refusal names its own shape — `hash` included,
    /// which `get_block_header_by_height`'s does not have.
    #[test]
    fn block_params_are_refused_naming_this_methods_shape() {
        assert_eq!(
            block_request(&json!(null)).unwrap(),
            GetBlockRequest::default()
        );
        assert_eq!(
            block_request(&json!({})).unwrap(),
            GetBlockRequest::default()
        );
        let parsed = block_request(&json!({"hash": "ab", "height": 7})).unwrap();
        assert_eq!(parsed.hash, "ab", "the handler parses the hash, not serde");
        for bad in [
            json!({"height": -1}),
            json!({"hash": 7}),
            json!([0]),
            json!(0),
        ] {
            let refusal = block_request(&bad).unwrap_err();
            assert_eq!(
                refusal,
                RpcFault::Refused(RpcRefusal::wrong_param(WRONG_BLOCK_PARAMS)),
                "{bad}"
            );
            let RpcFault::Refused(r) = refusal else {
                unreachable!()
            };
            assert!(
                r.message.contains("hash"),
                "the message names this method's hash field"
            );
        }
    }

    /// The 128-bit split is the wire's: low word, `0x`-hex whole, high word.
    #[test]
    fn difficulty_splits_the_way_the_wire_carries_it() {
        assert_eq!(split_128(1), (1, "0x1".to_owned(), 0));
        assert_eq!(
            split_128((1u128 << 70) + 12345),
            (12345, "0x400000000000003039".to_owned(), 64)
        );
        assert_eq!(
            split_128(u128::MAX),
            (u64::MAX, format!("0x{:x}", u128::MAX), u64::MAX)
        );
    }

    /// A height past the tip is the shared TOO_BIG_HEIGHT refusal, naming the
    /// top height — the same wording `on_get_block_hash` uses.
    #[test]
    fn header_past_the_tip_is_refused() {
        let f = header_facts();
        let err = get_block_header_by_height(&f, 9_000_000, false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                message: "Requested block height: 9000000 greater than current top block \
                          height: 1234609"
                    .to_owned(),
                data: None,
            })
        );
    }

    /// A store that cannot produce an in-range block keeps the C++ contract's
    /// INTERNAL_ERROR and wording, rather than the generic internal error a
    /// bare facts fault would get.
    #[test]
    fn header_inconsistent_store_keeps_the_contract_error() {
        let mut f = header_facts();
        f.hash_fault = Some(FactsFault::Inconsistent);
        let err = get_block_header_by_height(&f, 5, false).unwrap_err();
        assert_eq!(
            err,
            RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                message: "Internal error: can't get block by height. Height = 5.".to_owned(),
                data: None,
            })
        );
    }

    /// Any other facts fault stays a facts fault (a generic internal error),
    /// never a claim about the caller's height.
    #[test]
    fn header_other_faults_are_not_rendered_as_contract_errors() {
        let mut f = header_facts();
        f.hash_fault = Some(FactsFault::NotReady);
        assert_eq!(
            get_block_header_by_height(&f, 5, false),
            Err(RpcFault::Facts(FactsFault::NotReady))
        );
    }

    /// Params: one height parses; every other shape is WRONG_PARAM, including
    /// the negative the C++ hand-parser used to wrap into TOO_BIG_HEIGHT.
    #[test]
    fn block_hash_params_refuse_everything_but_one_height() {
        assert_eq!(
            get_block_hash_height(&serde_json::json!([1234])).unwrap(),
            1234
        );
        for bad in [
            serde_json::json!([]),
            serde_json::json!([1, 2]),
            serde_json::json!(["1"]),
            serde_json::json!([-1]),
            serde_json::json!(1234),
            serde_json::json!({}),
            serde_json::json!(null),
        ] {
            let err = get_block_hash_height(&bad).unwrap_err();
            assert_eq!(
                err,
                RpcFault::Refused(RpcRefusal::wrong_param("Wrong parameters, expected height")),
                "{bad} must be WRONG_PARAM"
            );
        }
    }

    // ── RK-5b: the header remainder ────────────────────────────────────────

    /// `fill_pow_hash` is the hash recorded at validation. Asking includes
    /// it. Not asking leaves the field empty.
    #[test]
    fn fill_pow_hash_is_the_recorded_hash() {
        let f = facts(true, 0);
        let filled = get_last_block_header(&f, true).expect("the recorded hash");
        assert!(filled.block_header.pow_hash.is_some());
        let bare = get_last_block_header(&f, false).expect("no hash asked");
        assert!(bare.block_header.pow_hash.is_none());
    }

    /// A bounded range within the header cap, asking for the recorded hash
    /// on every header, is served. The hash is a store read.
    #[test]
    fn a_bounded_header_range_serves_the_recorded_hash() {
        let f = facts(false, 0);
        let out = get_block_headers_range(
            &f,
            &GetBlockHeadersRangeRequest {
                start_height: 0,
                end_height: 2,
                fill_pow_hash: true,
            },
            true,
        )
        .expect("three headers are inside the 1,000-header cap");
        assert_eq!(out.headers.len(), 3);
        assert!(out.headers.iter().all(|header| header.pow_hash.is_some()));
    }

    /// A block arriving between choosing the tip and projecting it does not
    /// produce a header labelled "last" with `depth == 1`.
    ///
    /// **The defect is inherited, not introduced.** The C++ read
    /// `get_blockchain_top`, then `get_block_by_hash`, then computed depth
    /// from a third read of the chain height — the same three-snapshot shape.
    /// Rule 16: an inherited flow that contradicts the method's own contract
    /// is migrated rather than carried, and "last block header" answering
    /// with a block that is not last is exactly that.
    ///
    /// The fake grows its chain once, on the first header read, which is the
    /// state a constant-height double makes unrepresentable.
    #[test]
    fn a_block_arriving_mid_read_does_not_yield_a_stale_tip() {
        let f = facts(true, 0);
        let before = f.tip.as_ref().expect("a tip").chain_height;
        f.tip_growth_remaining.store(1, Ordering::Relaxed);

        let out = get_last_block_header(&f, false).expect("the tip, after one retry");
        // The header returned is the *new* tip, not the height chosen from
        // the pre-growth snapshot. One growth makes the old exclusive end
        // (`next_height`) the new tip ordinal.
        assert_eq!(out.block_header.height, before.next_height().to_raw());
        assert_eq!(
            out.block_header.depth, 0,
            "a header reported as the last block must be the last block"
        );
        // Two reads: the first saw the chain move, the second agreed with its
        // own bound. Asserted so a fix that merely widened a bound, without
        // re-reading, is distinguishable from one that converged.
        assert_eq!(f.header_reads.load(Ordering::Relaxed), 2);
    }

    /// A chain that moves on every attempt is answered, not looped over.
    #[test]
    fn a_chain_that_never_settles_is_refused_rather_than_spun_on() {
        let f = facts(true, 0);
        f.tip_growth_remaining.store(u64::MAX, Ordering::Relaxed);
        let out = get_last_block_header(&f, false);
        assert!(
            matches!(&out, Err(RpcFault::Refused(r)) if r.code == CORE_RPC_ERROR_CODE_CORE_BUSY),
            "{out:?}"
        );
        // Bounded: the refusal costs a fixed number of reads, so a node under
        // sustained block arrival cannot be made to spin here.
        assert_eq!(
            f.header_reads.load(Ordering::Relaxed),
            TIP_READ_ATTEMPTS as u64
        );
    }

    /// An unsynchronised node refuses to report a tip, rather than reporting
    /// the top of a partial chain.
    ///
    /// The C++ `CHECK_CORE_READY()` guarded **this method alone** among the
    /// slice's methods, and the reason survives: this is the one that answers
    /// "the tip", which on a syncing node is the top of what has arrived so
    /// far presented as the top of the chain. The other header methods take
    /// an explicit height or hash, where the caller named what it wanted.
    ///
    /// The C++ answered `status = BUSY` with a **default-constructed**
    /// header, and that was a live trap rather than a tidy convention: a
    /// client reading `block_header` without checking the status beside it
    /// was told the tip was a block of major version 0 with a zero hash. A
    /// refusal cannot be read as an answer.
    #[test]
    fn an_unsynchronized_node_refuses_to_report_a_tip() {
        let unsynced = facts(false, 900_000);
        let out = get_last_block_header(&unsynced, false);
        assert!(
            matches!(&out, Err(RpcFault::Refused(r)) if r.code == CORE_RPC_ERROR_CODE_CORE_BUSY),
            "{out:?}"
        );
        // No header was read: the refusal precedes the projection, so a
        // syncing node does not pay for a question it will not answer.
        assert_eq!(unsynced.header_reads.load(Ordering::Relaxed), 0);

        // The other three have no readiness check, because the C++ gave them
        // none — asserted, so that "port what is there" stays a fact about
        // this diff rather than a claim about it.
        let range = GetBlockHeadersRangeRequest {
            start_height: 0,
            end_height: 0,
            fill_pow_hash: false,
        };
        assert!(get_block_headers_range(&unsynced, &range, false).is_ok());
        assert!(get_fee_estimate(&unsynced, &GetFeeEstimateRequest::default()).is_ok());
        assert!(get_block_header_by_hash(
            &unsynced,
            &GetBlockHeaderByHashRequest {
                hashes: vec![],
                fill_pow_hash: false,
            },
            false,
        )
        .is_ok());
    }

    /// One miss does not discard the rest, and each slot names the hash it
    /// answers — the two properties the all-or-nothing C++ could not give.
    #[test]
    fn a_missing_hash_costs_only_its_own_slot() {
        let mut f = facts(false, 0);
        f.hash_chain_height = ChainCount::from_raw(1_234_567);
        let known = HashHex::from_bytes(patterned_hash().to_bytes());
        let absent = HashHex::from_bytes(tagged_hash(200).to_bytes());
        let request = GetBlockHeaderByHashRequest {
            hashes: vec![known, absent, known],
            fill_pow_hash: false,
        };
        let out = get_block_header_by_hash(&f, &request, false).expect("per-element");
        assert_eq!(out.block_headers.len(), 3, "one slot per requested hash");
        assert!(out.block_headers[0].block_header.is_some());
        assert!(
            out.block_headers[1].block_header.is_none(),
            "the miss is data, not a fault that discards its neighbours"
        );
        assert!(out.block_headers[2].block_header.is_some());
        assert_eq!(
            out.block_headers[1].hash, absent,
            "each slot names its hash"
        );
    }

    /// The span cap bounds the number of headers, not the difference between
    /// the endpoints. The C++ tested the difference, which let 1001 through
    /// against a cap of 1000.
    #[test]
    fn the_header_range_cap_counts_headers_not_the_gap() {
        let f = facts(false, 0);
        let range = |start: u64, end: u64| GetBlockHeadersRangeRequest {
            start_height: start,
            end_height: end,
            fill_pow_hash: false,
        };
        // Exactly at the cap: 1000 headers, heights 0..=999.
        assert!(get_block_headers_range(&f, &range(0, 999), true).is_ok());
        // One more header — the value the C++ admitted.
        assert!(matches!(
            get_block_headers_range(&f, &range(0, 1000), true),
            Err(RpcFault::Refused(_))
        ));
        // Unrestricted, neither is capped.
        assert!(get_block_headers_range(&f, &range(0, 1000), false).is_ok());
        // An inverted range is refused before any chain read.
        assert!(matches!(
            get_block_headers_range(&f, &range(5, 4), false),
            Err(RpcFault::Refused(_))
        ));
    }

    /// A range past the tip is refused **without reading a single header**.
    ///
    /// The C++ bounded both endpoints against the chain height in one O(1)
    /// test before its loop; the first port of this method kept only the
    /// ordering check and discovered the overrun inside the loop, one height
    /// at a time. On the unrestricted listener — where the span cap does not
    /// apply — `start_height = 0, end_height = u64::MAX` therefore walked the
    /// whole chain, a lock acquisition and a block read per height, before
    /// refusing. Found by review, not by a test, because **an assertion on
    /// the error code cannot tell an O(1) refusal from one that did all the
    /// work first**: both return the same refusal. The count is the only
    /// observable that separates them, which is why the fake now carries one.
    #[test]
    fn a_range_past_the_tip_is_refused_before_any_header_is_read() {
        let f = facts(false, 0);
        let reads = || f.header_reads.load(Ordering::Relaxed);
        let range = |start: u64, end: u64| GetBlockHeadersRangeRequest {
            start_height: start,
            end_height: end,
            fill_pow_hash: false,
        };

        let before = reads();
        assert!(matches!(
            get_block_headers_range(&f, &range(0, u64::MAX), false),
            Err(RpcFault::Refused(refusal)) if refusal.code == CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT
        ));
        assert_eq!(
            reads(),
            before,
            "an unbounded range must cost no header reads"
        );

        // Asking for the count as an ordinal is past the exclusive end.
        let chain = f.tip.as_ref().expect("a tip").chain_height;
        let past = chain.next_height().to_raw();
        let before = reads();
        assert!(matches!(
            get_block_headers_range(&f, &range(past, past), false),
            Err(RpcFault::Refused(_))
        ));
        assert_eq!(reads(), before, "the exclusive end is not readable");

        // And the last valid height still answers, so the bound is not
        // off by one in the other direction.
        let last = chain.tip().expect("non-empty fake").to_raw();
        let before = reads();
        assert!(get_block_headers_range(&f, &range(last, last), false).is_ok());
        assert_eq!(reads(), before + 1, "exactly one header for one height");
    }

    /// A height that vanishes between the bound and the loop is a caller
    /// error, not a store fault.
    ///
    /// **The pre-loop bound is a fast refusal, not a guarantee.** The tip can
    /// move down underneath it — a reorg onto a shorter heavier chain, or an
    /// operator `pop_blocks` — so the loop still has to say what a missing
    /// header means. On the height path the shim returns `found == 0` for
    /// exactly one condition (`height >= chain_height`, read inside that
    /// call) and reports a store that cannot produce a block it claims to
    /// hold as an *error*, which `?` propagates before this arm is reached.
    /// So this arm can only be the chain shortening, and reporting it as
    /// `Inconsistent` would hand the caller a generic internal error for a
    /// benign race whose remedy is to re-ask.
    ///
    /// The fake reproduces exactly that: the tip it reports on `chain_tip`
    /// is above the height its header arm will still answer for.
    #[test]
    fn a_height_that_vanishes_under_the_bound_is_a_caller_error() {
        let mut f = facts(true, 0);
        // The bound sees 1_234_567; the header arm holds only 1_000 blocks.
        f.hash_chain_height = ChainCount::from_raw(1_000);
        let out = get_block_headers_range(
            &f,
            &GetBlockHeadersRangeRequest {
                start_height: 999,
                end_height: 1_000,
                fill_pow_hash: false,
            },
            false,
        );
        let Err(RpcFault::Refused(refusal)) = out else {
            panic!("a vanished height is a refusal, not a fault: {out:?}");
        };
        assert_eq!(refusal.code, CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT);
        // Names the height that has gone and the tip as it now stands, so
        // the caller can re-ask rather than guess.
        assert!(refusal.message.contains("1000"), "{}", refusal.message);
        assert!(refusal.message.contains("999"), "{}", refusal.message);
    }

    /// The tiers are reachable by name; the scalar `fee` and the mask are
    /// gone, and the reply is the three tiers and the status alone.
    #[test]
    fn the_fee_reply_names_its_tiers() {
        let f = facts(false, 0);
        let out = get_fee_estimate(&f, &GetFeeEstimateRequest::default()).expect("fees");
        assert_eq!(out.fees.get(shekyl_rpc_types::FeeTier::Low), 10);
        assert_eq!(out.fees.get(shekyl_rpc_types::FeeTier::High), 40);
        assert_eq!(
            serde_json::to_value(&out).expect("serializes"),
            json!({"status": "OK", "fees": [10, 20, 40]})
        );
    }

    // ── RK-5a: the p2p methods ─────────────────────────────────────────────

    /// In-memory [`P2pFacts`]. Records `public_only` because that argument
    /// selects a **different p2p call**, not a filter — a handler that
    /// forwarded a constant would pass every assertion about the entries it
    /// got back.
    pub(crate) struct FakeP2p {
        pub net: Result<NetStats, FactsFault>,
        pub connections: Result<ConnectionsSnapshot, FactsFault>,
        pub peers: Result<P2pRead<Vec<crate::core::PeerEntry>>, FactsFault>,
        pub state: Result<P2pRead<()>, FactsFault>,
        pub asked_public_only: AtomicBool,
    }

    impl Default for FakeP2p {
        fn default() -> Self {
            Self {
                net: Ok(NetStats {
                    start_time: 1_788_202_424,
                    total_packets_in: 101,
                    total_bytes_in: 202_020,
                    total_packets_out: 303,
                    total_bytes_out: 404_040,
                }),
                connections: Ok(ConnectionsSnapshot {
                    now: 0,
                    connections: Vec::new(),
                }),
                peers: Ok(P2pRead::Running(Vec::new())),
                state: Ok(P2pRead::Running(())),
                asked_public_only: AtomicBool::new(false),
            }
        }
    }

    impl P2pFacts for FakeP2p {
        fn net_stats(&self) -> Result<NetStats, FactsFault> {
            self.net
        }
        fn connections(&self) -> Result<ConnectionsSnapshot, FactsFault> {
            self.connections.clone()
        }
        fn peer_list(
            &self,
            public_only: bool,
        ) -> Result<P2pRead<Vec<crate::core::PeerEntry>>, FactsFault> {
            self.asked_public_only.store(public_only, Ordering::SeqCst);
            self.peers.clone()
        }
        fn p2p_state(&self) -> Result<P2pRead<()>, FactsFault> {
            self.state.clone()
        }
        fn stem_tallies(&self) -> Result<shekyl_rpc_types::StemTallies, FactsFault> {
            Ok(shekyl_rpc_types::StemTallies::default())
        }
    }

    /// In-memory chain sync view.
    pub(crate) struct FakeView(pub Result<SyncViewFacts, FactsFault>);

    impl FakeView {
        /// No session: a node chain sync holds nothing for.
        pub(crate) fn empty() -> Self {
            Self(Ok(SyncViewFacts {
                state: ChainSyncState::NoView,
                stalled: false,
                target: 1_234_567,
                sessions: Vec::new(),
            }))
        }

        /// One session, for [`connection_facts`]'s connection: it claims
        /// 1,234,567 blocks and its header run is reachable.
        pub(crate) fn one() -> Self {
            Self(Ok(SyncViewFacts {
                state: ChainSyncState::Behind,
                stalled: false,
                target: 1_234_600,
                sessions: vec![SyncSessionFacts {
                    connection_id: connection_facts().connection_id,
                    claimed_height: Some(1_234_567),
                    mode: SyncMode::Reachable,
                    header_request: Some(RequestTiming {
                        age_ms: 250,
                        due_in_ms: 257_750,
                    }),
                    body_requests: vec![BodySpanFacts {
                        start_height: 1_234_568,
                        count: 20,
                        planned_bytes: 8_388_608,
                        timing: RequestTiming {
                            age_ms: 1_500,
                            due_in_ms: 1_022_500,
                        },
                    }],
                    rate: Some(4096),
                }],
            }))
        }
    }

    impl crate::sync_facts::SyncViewRead for FakeView {
        fn sync_view(&self) -> Result<SyncViewFacts, FactsFault> {
            self.0.clone()
        }
    }

    /// A connection whose every derived field has a distinct, checkable
    /// input. `started` is 1000 and the tests read it at 1600, so the
    /// connection is 600 seconds old.
    fn connection_facts() -> crate::core::ConnectionFacts {
        crate::core::ConnectionFacts {
            address: "192.0.2.7:18080".to_owned(),
            host: "192.0.2.7".to_owned(),
            connection_id: [
                0x15, 0x1c, 0x23, 0x2a, 0x31, 0x38, 0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69, 0x70,
                0x77, 0x7e,
            ],
            started: 1000,
            last_recv: 1590,
            last_send: 1580,
            // 600 s old, so this is 2048 B/s -> 2 KiB/s after the two
            // truncating divisions.
            recv_count: 600 * 2048,
            send_count: 600 * 1024,
            current_speed_down: 4096.0,
            current_speed_up: 2048.0,
            port: 18080,
            address_type: ADDRESS_TYPE_IPV4,
            incoming: true,
            localhost: false,
            local_ip: true,
        }
    }

    #[test]
    fn net_stats_reports_the_five_counters() {
        let facts = FakeP2p::default();
        let res = get_net_stats(&facts).expect("net stats");
        assert!(res.status.is_ok());
        assert_eq!(res.start_time, 1_788_202_424);
        assert_eq!(res.total_bytes_in, 202_020);
        assert_eq!(res.total_bytes_out, 404_040);
        assert_eq!(res.total_packets_in, 101);
        assert_eq!(res.total_packets_out, 303);
    }

    /// The derivations that used to be inline C++, each against the one
    /// instant the list was read at.
    #[test]
    fn a_connection_derives_its_times_and_rates_from_one_instant() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let res = get_connections(&facts, &FakeView::one())
            .expect("connections")
            .into_running()
            .expect("P2P runs");
        let c = &res.connections[0];

        assert_eq!(c.live_time, 600);
        assert_eq!(c.recv_idle_time, 10, "1600 - max(started, last_recv)");
        assert_eq!(c.send_idle_time, 20);
        // bytes / seconds / 1024, in that order and both truncating.
        assert_eq!(c.avg_download, 2);
        assert_eq!(c.avg_upload, 1);
        assert_eq!(c.current_download, 4);
        assert_eq!(c.current_upload, 2);
        // Zero-padded to 16, as `peerid_to_string` pads.
        assert_eq!(c.connection_id, "151c232a31383f464d545b626970777e");
        // The claim's count and the session's mode, from chain sync's view.
        assert_eq!(c.state, Some(SyncMode::Reachable));
        assert_eq!(c.height, Some(1_234_567));
        // ipv4: `ip` echoes the host and `port` is the number as a string.
        assert_eq!(c.ip, "192.0.2.7");
        assert_eq!(c.port, "18080");
    }

    /// A connection chain sync does not hold, such as one before its
    /// handshake, has no claim and no mode: both are null, never a zero
    /// height or some mode's name.
    #[test]
    fn a_connection_chain_sync_does_not_hold_has_null_height_and_state() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts, &FakeView::empty())
            .expect("connections")
            .into_running()
            .expect("P2P runs")
            .connections[0];
        assert_eq!(c.state, None);
        assert_eq!(c.height, None);
        let json = serde_json::to_value(c).expect("json");
        assert!(json["height"].is_null());
        assert!(json["state"].is_null());
        // `support_flags` left the P2P wire (2026-10-19).
        assert!(json.get("support_flags").is_none());
    }

    /// A connection younger than a second divides by zero in the naive form.
    /// The averages are 0, not a panic and not a wrapped maximum.
    #[test]
    fn a_brand_new_connection_reports_zero_averages() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1000,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts, &FakeView::empty())
            .expect("connections")
            .into_running()
            .expect("P2P runs")
            .connections[0];
        assert_eq!(c.live_time, 0);
        assert_eq!(c.avg_download, 0);
        assert_eq!(c.avg_upload, 0);
    }

    /// A clock that moved backwards. The C++ subtracted unsigned and wrapped,
    /// reporting an idle time of some hundreds of years; every elapsed value
    /// here saturates at zero instead.
    #[test]
    fn a_backwards_clock_saturates_rather_than_wrapping() {
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 500,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts, &FakeView::empty())
            .expect("connections")
            .into_running()
            .expect("P2P runs")
            .connections[0];
        assert_eq!(c.live_time, 0);
        assert_eq!(c.recv_idle_time, 0);
        assert_eq!(c.send_idle_time, 0);
    }

    /// Only the ipv4 arm carries `ip` and `port`; every other address type
    /// carries them empty, and `address` is the whole rendering instead.
    #[test]
    fn a_non_ipv4_connection_carries_no_ip_or_port() {
        let mut raw = connection_facts();
        raw.address_type = 4; // tor
        raw.address = "abcdefghijklmnop.onion:18080".to_owned();
        raw.host = "abcdefghijklmnop.onion".to_owned();
        let facts = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![raw],
            }),
            ..FakeP2p::default()
        };
        let c = &get_connections(&facts, &FakeView::empty())
            .expect("connections")
            .into_running()
            .expect("P2P runs")
            .connections[0];
        assert_eq!(c.ip, "");
        assert_eq!(c.port, "");
        assert_eq!(c.address, "abcdefghijklmnop.onion:18080");
        assert_eq!(c.host, "abcdefghijklmnop.onion");
    }

    /// `include_blocked` is applied here, on the request, and the white/gray
    /// split comes from the entry's own flag.
    #[test]
    fn the_peer_list_splits_by_list_and_filters_blocked_on_request() {
        let peer = |n: u64, white: bool, blocked: bool| crate::core::PeerEntry {
            host: format!("192.0.2.{n}"),
            ip: 0,
            port: 18080,
            white,
            blocked,
        };
        let facts = FakeP2p {
            peers: Ok(P2pRead::Running(vec![
                peer(1, true, false),
                peer(2, true, true),
                peer(3, false, false),
                peer(4, false, true),
            ])),
            ..FakeP2p::default()
        };

        let hidden = get_peer_list(
            &GetPeerListRequest {
                public_only: true,
                include_blocked: false,
            },
            &facts,
        )
        .expect("peer list")
        .into_running()
        .expect("P2P runs");
        assert_eq!(hidden.white_list.len(), 1);
        assert_eq!(hidden.gray_list.len(), 1);
        assert_eq!(hidden.white_list[0].host, "192.0.2.1");
        assert_eq!(hidden.gray_list[0].host, "192.0.2.3");
        assert!(facts.asked_public_only.load(Ordering::SeqCst));

        let shown = get_peer_list(
            &GetPeerListRequest {
                public_only: false,
                include_blocked: true,
            },
            &facts,
        )
        .expect("peer list")
        .into_running()
        .expect("P2P runs");
        assert_eq!(shown.white_list.len(), 2);
        assert_eq!(shown.gray_list.len(), 2);
        assert!(
            !facts.asked_public_only.load(Ordering::SeqCst),
            "public_only reaches the facts call, which chooses a different p2p read"
        );
    }

    /// **A daemon started offline answers `offline` alone on all three
    /// methods** (Rick, 2026-10-14), and reads no connection, span or chain
    /// for it: every other fact here is a fault, so a read would refuse.
    #[test]
    fn an_offline_daemon_answers_the_state_on_every_p2p_method() {
        let off = FakeP2p {
            connections: Err(FactsFault::Internal),
            peers: Ok(P2pRead::Offline),
            state: Ok(P2pRead::Offline),
            ..FakeP2p::default()
        };
        assert_eq!(
            get_connections(&off, &FakeView::empty()).expect("a state"),
            P2pReply::Offline
        );
        assert_eq!(
            get_peer_list(&GetPeerListRequest::default(), &off).expect("a state"),
            P2pReply::Offline
        );
        assert_eq!(
            sync_info(&facts(false, 0), &FakeView::empty(), &off).expect("a state"),
            P2pReply::Offline
        );
    }

    /// An online daemon whose P2P state cannot be read is a fault on every
    /// method, never an empty reply.
    #[test]
    fn an_unreadable_p2p_state_is_a_fault_not_an_empty_reply() {
        let broken = FakeP2p {
            peers: Err(FactsFault::Internal),
            state: Err(FactsFault::NotReady),
            ..FakeP2p::default()
        };
        assert!(get_connections(&broken, &FakeView::empty()).is_err());
        assert!(get_peer_list(&GetPeerListRequest::default(), &broken).is_err());
        assert!(sync_info(&facts(false, 0), &FakeView::empty(), &broken).is_err());
    }

    /// The lifetime average, including the two inputs that would divide by
    /// zero. Total by construction, so there is no guard to accidentally
    /// move away from the division.
    #[test]
    fn a_lifetime_average_is_total() {
        assert_eq!(average_kib(600 * 2048, 600), 2);
        assert_eq!(average_kib(600 * 1024, 600), 1);
        assert_eq!(average_kib(1023, 1), 0, "truncates to whole KiB");
        assert_eq!(average_kib(u64::MAX, 0), 0, "a zero-length connection");
        assert_eq!(average_kib(0, 0), 0);
    }

    /// The conversion the C++ made with an undefined cast.
    #[test]
    fn a_connection_speed_becomes_whole_kib_totally() {
        assert_eq!(kib_per_second(0.0), 0);
        assert_eq!(kib_per_second(1023.9), 0, "truncates, not rounds");
        assert_eq!(kib_per_second(1024.0), 1);
        assert_eq!(kib_per_second(4096.0), 4);
        // The division is in floating point, as the C++ did it, so this is
        // `trunc(x / 1024)` and not `trunc(x) / 1024`.
        assert_eq!(kib_per_second(2047.9), 1);
        assert_eq!(kib_per_second(-1.0), 0, "negative is clamped, not cast");
        assert_eq!(kib_per_second(f64::NAN), 0);
        assert_eq!(kib_per_second(f64::INFINITY), 0, "not finite");
        assert_eq!(
            kib_per_second(1e30),
            u64::MAX,
            "saturates rather than wraps"
        );
    }

    /// `sync_info` is chain sync's view (3.68): the chain's height, the
    /// view's target, state and stall, and one row per session the board
    /// still holds, with its address from the board.
    #[test]
    fn sync_info_renders_the_view_and_joins_the_board() {
        let p2p = FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now: 1600,
                connections: vec![connection_facts()],
            }),
            ..FakeP2p::default()
        };
        let res = sync_info(&facts(false, 0), &FakeView::one(), &p2p)
            .expect("sync info")
            .into_running()
            .expect("P2P runs");
        assert_eq!(res.height, 1_234_567);
        assert_eq!(res.target_height, 1_234_600);
        assert_eq!(res.state, ChainSyncState::Behind);
        assert!(!res.stalled);
        assert_eq!(res.peers.len(), 1);
        let peer = &res.peers[0];
        assert_eq!(peer.connection_id, "151c232a31383f464d545b626970777e");
        assert_eq!(peer.address, "192.0.2.7:18080");
        assert_eq!(peer.claimed_height, Some(1_234_567));
        assert_eq!(peer.mode, SyncMode::Reachable);
        assert_eq!(peer.header_request.map(|r| r.due_in_ms), Some(257_750));
        assert_eq!(peer.body_requests.len(), 1);
        assert_eq!(peer.body_requests[0].start_height, 1_234_568);
        assert_eq!(peer.rate, Some(4096));
    }

    /// A session the view lists and the board no longer holds closed
    /// between the two reads: it is left out, not shown without an address.
    #[test]
    fn a_session_gone_from_the_board_is_left_out() {
        let res = sync_info(&facts(false, 0), &FakeView::one(), &FakeP2p::default())
            .expect("sync info")
            .into_running()
            .expect("P2P runs");
        assert!(res.peers.is_empty());
    }

    /// A stalled view says so on the wire.
    #[test]
    fn a_stall_is_reported() {
        let mut view = FakeView::empty().0.expect("a view");
        view.state = ChainSyncState::Behind;
        view.stalled = true;
        let res = sync_info(&facts(false, 0), &FakeView(Ok(view)), &FakeP2p::default())
            .expect("sync info")
            .into_running()
            .expect("P2P runs");
        assert!(res.stalled);
        assert_eq!(serde_json::to_value(&res).unwrap()["stalled"], true);
    }
}
