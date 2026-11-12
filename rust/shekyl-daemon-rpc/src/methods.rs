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
    /// The bounded callers' one shard fetch is in flight (IG-Q90).
    pub const BOUND_SHARD: &str = "bound.shard";
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
        BlockLookup, ChainTip, DaemonIdentity, FeeEstimate, NetStats,
    };
    use crate::core::ConnectionsSnapshot;
    use crate::sync_facts::{BodySpanFacts, RequestTiming, SyncSessionFacts, SyncViewFacts};
    use shekyl_rpc_types::wire::p2p::{SyncMode, SyncState};
    use shekyl_types::{
        BlockCount, BlockHash, BlockHeight, ChainCount, CurveTreeRoot, SectionRoot, TxHash,
    };
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
        /// The last `pow` switch `block_header_at` was asked for.
        pub asked_pow: AtomicBool,
        /// The hash `block_at` was asked for, when it was asked by hash.
        pub asked_hash: std::sync::Mutex<Option<[u8; 32]>>,
        /// When set, `block_at` faults instead of answering.
        pub block_fault: Option<FactsFault>,
        /// How many times `block_header_at` was called.
        ///
        /// A *count*, not a last-value, because the property
        /// `block_header_list` owes is about work not done: a range
        /// past the tip must be refused before any per-height read. An
        /// assertion on the error code alone cannot tell an O(1) refusal
        /// from one that walked the chain first and refused at the end.
        pub header_reads: AtomicU64,
        /// How many more header reads see the chain grow by one block first.
        ///
        /// **The input a fixed-height double cannot express.** `block_header_show`
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
                    bundle_references: Vec::new(),
                    bundle_bodies: Vec::new(),
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
                halt: None,
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
            section_root: SectionRoot::from_bytes(tagged_bytes(53)),
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
        fn stem_tallies(&self) -> Result<p2p::RelayStats, FactsFault> {
            Ok(p2p::RelayStats {
                floor: Vec::new(),
                tally: Vec::new(),
            })
        }
    }

    /// In-memory chain sync view.
    pub(crate) struct FakeView(pub Result<SyncViewFacts, FactsFault>);

    impl FakeView {
        /// No session: a node chain sync holds nothing for.
        pub(crate) fn empty() -> Self {
            Self(Ok(SyncViewFacts {
                state: SyncState::Unpeered,
                stalled: false,
                target: 1_234_567,
                sessions: Vec::new(),
            }))
        }

        /// One session, for [`connection_facts`]'s connection: it claims
        /// 1,234,567 blocks and its header run is reachable.
        pub(crate) fn one() -> Self {
            Self(Ok(SyncViewFacts {
                state: SyncState::Behind,
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
            // epee's ipv4 address-type id.
            address_type: 1,
            incoming: true,
            localhost: false,
            local_ip: true,
        }
    }

    // ── the fault and its class (RW-Q3) ────────────────────────────────

    /// **One refusal per class, each with its dotted code.** A fault the
    /// node caused carries its stage and no request detail; a store
    /// contradiction carries its operands. The edit that turns this red is a
    /// fault mapped to another class, or a code without its segment.
    #[test]
    fn every_fault_is_its_class_and_its_dotted_code() {
        use shekyl_rpc_types::errors::ErrorClass as C;
        let cases: Vec<(RpcFault, C, &str)> = vec![
            (
                RpcFault::Facts(FactsFault::NotReady),
                C::NotReady,
                codes::DAEMON_UNREADY,
            ),
            (
                RpcFault::Facts(FactsFault::Internal),
                C::Internal,
                codes::DAEMON_INTERNAL,
            ),
            (
                RpcFault::Facts(FactsFault::Inconsistent),
                C::StoreFault,
                codes::CHAIN_INCONSISTENT,
            ),
            (
                RpcFault::Facts(FactsFault::StoreUnreadable),
                C::StoreFault,
                codes::CHAIN_UNREADABLE,
            ),
            (
                RpcFault::Store(StoreFault::SupplyInvariant {
                    coins_generated: AtomicUnits::from_raw(5),
                    total_burned: AtomicUnits::from_raw(9),
                    chain_height: ChainCount::from_raw(12),
                }),
                C::StoreFault,
                codes::CHAIN_SUPPLY_INVARIANT,
            ),
            (
                RpcFault::Internal(InternalFault::Serialize),
                C::Internal,
                codes::DAEMON_INTERNAL,
            ),
            (
                bound_exceeded(codes::BOUND_TX, "transactions", 100, 101),
                C::OverResourceBound,
                codes::BOUND_TX,
            ),
            (p2p_offline(), C::RefusedByMethod, codes::P2P_OFFLINE),
        ];
        for (fault, class, code) in cases {
            let error = fault.clone().into_error();
            assert_eq!(error.class, class, "{fault:?}");
            assert_eq!(error.diagnostic.code, code, "{fault:?}");
            assert!(code.contains('.'), "a dotted code: {code}");
        }
        let supply = RpcFault::Store(StoreFault::SupplyInvariant {
            coins_generated: AtomicUnits::from_raw(5),
            total_burned: AtomicUnits::from_raw(9),
            chain_height: ChainCount::from_raw(12),
        })
        .into_error();
        assert_eq!(supply.diagnostic.parameter["total_burned"], "9");
        assert_eq!(supply.diagnostic.parameter["chain_height"], "12");
        let internal = RpcFault::Internal(InternalFault::Join).into_error();
        assert_eq!(internal.diagnostic.parameter["stage"], "join");
        let bound = bound_exceeded(codes::BOUND_TX, "transactions", 100, 101).into_error();
        assert_eq!(bound.diagnostic.parameter["bound"], "100");
        assert_eq!(bound.diagnostic.parameter["asked"], "101");
    }

    // ── the p2p methods ─────────────────────────────────────────────────

    #[test]
    fn p2p_stats_reports_the_five_counters() {
        let res = p2p_stats(&FakeP2p::default()).expect("net stats");
        assert_eq!(res.started, Time(1_788_202_424));
        assert_eq!(res.download, Size(202_020));
        assert_eq!(res.upload, Size(404_040));
        assert_eq!(res.download_packets, Count(101));
        assert_eq!(res.upload_packets, Count(303));
    }

    fn one_connection(now: u64, raw: crate::core::ConnectionFacts) -> FakeP2p {
        FakeP2p {
            connections: Ok(ConnectionsSnapshot {
                now,
                connections: vec![raw],
            }),
            ..FakeP2p::default()
        }
    }

    /// The derivations, each against the one instant the list was read at.
    #[test]
    fn a_connection_derives_its_times_and_rates_from_one_instant() {
        let res = peer_connections(&one_connection(1600, connection_facts()), &FakeView::one())
            .expect("connections");
        let c = &res[0];
        assert_eq!(c.age, Duration(600));
        assert_eq!(
            c.download_idle,
            Duration(10),
            "1600 - max(started, last_recv)"
        );
        assert_eq!(c.upload_idle, Duration(20));
        assert_eq!(c.download_speed_average, Rate(2048), "bytes per second");
        assert_eq!(c.upload_speed_average, Rate(1024));
        assert_eq!(c.download_speed_current, Rate(4096));
        assert_eq!(c.upload_speed_current, Rate(2048));
        assert_eq!(c.id.0, "151c232a31383f464d545b626970777e");
        assert_eq!(c.mode.0, Some(SyncMode::Reachable));
        // The claim's count as the tip it claims (IG-Q45).
        assert_eq!(c.height.0, Some(Height(1_234_566)));
        assert!(c.inbound && c.local);
        assert_eq!(c.endpoint.0, "192.0.2.7:18080");
        assert_eq!(c.connector, p2p::Connector::Clearnet);
    }

    /// A connection chain sync does not hold has no claim and no mode: both
    /// `null`, never a zero height or some mode's name.
    #[test]
    fn a_connection_chain_sync_does_not_hold_has_null_height_and_mode() {
        let res = peer_connections(
            &one_connection(1600, connection_facts()),
            &FakeView::empty(),
        )
        .expect("connections");
        let json = serde_json::to_value(&res[0]).expect("json");
        assert!(json["height"].is_null());
        assert!(json["mode"].is_null());
    }

    /// A connection younger than a second divides by zero in the naive form.
    #[test]
    fn a_brand_new_connection_reports_zero_averages() {
        let res = peer_connections(
            &one_connection(1000, connection_facts()),
            &FakeView::empty(),
        )
        .expect("connections");
        assert_eq!(res[0].age, Duration(0));
        assert_eq!(res[0].download_speed_average, Rate(0));
        assert_eq!(res[0].upload_speed_average, Rate(0));
    }

    /// A clock that moved backwards saturates at zero rather than wrapping.
    #[test]
    fn a_backwards_clock_saturates_rather_than_wrapping() {
        let res = peer_connections(&one_connection(500, connection_facts()), &FakeView::empty())
            .expect("connections");
        assert_eq!(res[0].age, Duration(0));
        assert_eq!(res[0].download_idle, Duration(0));
        assert_eq!(res[0].upload_idle, Duration(0));
    }

    /// A Tor connection names its connector, and its endpoint is the onion.
    #[test]
    fn a_tor_connection_names_its_connector() {
        let mut raw = connection_facts();
        raw.address_type = ADDRESS_TYPE_TOR;
        raw.address = "abcdefghijklmnop.onion:18080".to_owned();
        let res =
            peer_connections(&one_connection(1600, raw), &FakeView::empty()).expect("connections");
        assert_eq!(res[0].connector, p2p::Connector::Tor);
        assert_eq!(res[0].endpoint.0, "abcdefghijklmnop.onion:18080");
    }

    /// One list, each entry naming its tier (IG-Q51); a blocked host is
    /// never listed; `local` reaches the facts call, which chooses a
    /// different p2p read.
    #[test]
    fn the_peer_list_names_tiers_and_leaves_out_the_blocked() {
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
        let list = peer_list(&facts, &p2p::PeerListQuery { local: false }).expect("peer list");
        assert_eq!(
            list,
            vec![
                p2p::PeerEntry {
                    endpoint: Endpoint("192.0.2.1:18080".to_owned()),
                    tier: p2p::Tier::White,
                },
                p2p::PeerEntry {
                    endpoint: Endpoint("192.0.2.3:18080".to_owned()),
                    tier: p2p::Tier::Gray,
                },
            ]
        );
        assert!(facts.asked_public_only.load(Ordering::SeqCst));
        peer_list(&facts, &p2p::PeerListQuery { local: true }).expect("peer list");
        assert!(!facts.asked_public_only.load(Ordering::SeqCst));
        // An IPv6 host takes brackets.
        assert_eq!(endpoint("2001:db8::1", 18080).0, "[2001:db8::1]:18080");
    }

    /// **A daemon started offline refuses every p2p read as `p2p.offline`**
    /// (IG-Q85), and reads no connection, span or chain for it: every other
    /// fact here is a fault, so a read would refuse otherwise.
    #[test]
    fn an_offline_daemon_refuses_every_p2p_read_as_offline() {
        let off = FakeP2p {
            connections: Err(FactsFault::Internal),
            peers: Ok(P2pRead::Offline),
            state: Ok(P2pRead::Offline),
            ..FakeP2p::default()
        };
        let offline = |r: Result<(), RpcFault>| {
            assert_eq!(
                r.expect_err("refused").into_error().diagnostic.code,
                codes::P2P_OFFLINE
            );
        };
        offline(peer_connections(&off, &FakeView::empty()).map(drop));
        offline(peer_list(&off, &p2p::PeerListQuery { local: false }).map(drop));
        let chain = facts(false, 0);
        offline(sync_status(&chain, &FakeView::empty(), &off).map(drop));
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
        assert!(peer_connections(&broken, &FakeView::empty()).is_err());
        assert!(peer_list(&broken, &p2p::PeerListQuery { local: false }).is_err());
        assert!(sync_status(&facts(false, 0), &FakeView::empty(), &broken).is_err());
    }

    /// A rate estimator's `f64` becomes a whole byte rate totally.
    #[test]
    fn a_connection_speed_becomes_a_whole_rate_totally() {
        assert_eq!(per_second(0.0), Rate(0));
        assert_eq!(per_second(1023.9), Rate(1023), "truncates, not rounds");
        assert_eq!(per_second(-1.0), Rate(0), "negative is clamped, not cast");
        assert_eq!(per_second(f64::NAN), Rate(0));
        assert_eq!(per_second(f64::INFINITY), Rate(0), "not finite");
        assert_eq!(
            per_second(1e30),
            Rate(u64::MAX),
            "saturates rather than wraps"
        );
    }

    /// `sync_status` is chain sync's view: the tip, the view's target as a
    /// tip, its state and stall, and one session per row the board still
    /// holds, with the endpoint from the board and request ages in seconds
    /// (`due` rounds up, IG-Q80).
    #[test]
    fn sync_status_renders_the_view_and_joins_the_board() {
        let res = sync_status(
            &facts(false, 0),
            &FakeView::one(),
            &one_connection(1600, connection_facts()),
        )
        .expect("sync status");
        assert_eq!(res.height, Height(1_234_566));
        assert_eq!(res.target_height, Height(1_234_599));
        assert_eq!(res.state, SyncState::Behind);
        assert!(!res.stalled);
        let session = &res.session[0];
        assert_eq!(session.connection.0, "151c232a31383f464d545b626970777e");
        assert_eq!(session.endpoint.0, "192.0.2.7:18080");
        assert_eq!(session.height.0, Some(Height(1_234_566)));
        assert_eq!(session.mode, SyncMode::Reachable);
        let header = session.header.0.clone().expect("a header read");
        assert_eq!((header.age, header.due), (Duration(0), Duration(258)));
        assert_eq!(session.span[0].from, Height(1_234_568));
        assert_eq!(session.span[0].blocks, Count(20));
        assert_eq!(session.download_speed.0, Some(Rate(4096)));
    }

    /// A session the view lists and the board no longer holds closed
    /// between the two reads: it is left out, not shown without an endpoint.
    #[test]
    fn a_session_gone_from_the_board_is_left_out() {
        let res = sync_status(&facts(false, 0), &FakeView::one(), &FakeP2p::default())
            .expect("sync status");
        assert!(res.session.is_empty());
    }

    /// A stalled view says so on the wire.
    #[test]
    fn a_stall_is_reported() {
        let mut view = FakeView::empty().0.expect("a view");
        view.state = SyncState::Behind;
        view.stalled = true;
        let res = sync_status(&facts(false, 0), &FakeView(Ok(view)), &FakeP2p::default())
            .expect("sync status");
        assert_eq!(serde_json::to_value(&res).unwrap()["stalled"], true);
    }
}
