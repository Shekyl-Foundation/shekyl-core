// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mining methods (`DRS_X_STORE_FLIP.md` DX-Q3, b3), over the node's
//! [`MiningFacts`] and [`DoorFacts`]. JSON-RPC and the REST mining routes
//! dispatch here. Each failure is an RW-Q3 class with a typed diagnostic
//! ([`codes`]).
//!
//! `block_template` reads the job the node posted; it builds nothing (N2),
//! and `block_template` folded into it (IG-Q46). The methods that wait or
//! join are `async`: `block_submit` and `dev_block_generate` wait on the
//! node, and `mine_start`, `mine_stop` and `dev_block_generate` run the
//! miner's start and stop, which spawn and join threads, on a blocking
//! thread of their own. Every other read is short.

use std::num::NonZeroUsize;

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::hex128::HexU128;
use shekyl_rpc_types::kinds::{Address, Bytes, Count, Done, Duration, Height, Integer, Size};
use shekyl_rpc_types::method::Armed;
use shekyl_rpc_types::wire::{block, node};
use shekyl_rpc_types::HashHex;
use shekyl_types::{BlockCount, BlockHash, ChainCount};
use shekyl_units::{wire::AtomicUnitsString, AtomicUnits};

use crate::chain_facts::{ChainFacts, FactsFault};
use crate::handles::{DoorFacts, MiningFacts, MiningHandle};
use crate::mining_facts::{LocalOutcome, PopOutcome};

/// The mining methods' diagnostic codes, each stated once.
pub mod codes {
    /// A defect in the node.
    pub const INTERNAL: &str = crate::methods::codes::DAEMON_INTERNAL;
    /// No `mine-address` row.
    pub const ADDRESS_UNSET: &str = "mine.address.unset";
    /// Chain sync does not say the node is synced.
    pub const SYNCING: &str = "mine.syncing";
    /// The pool file faulted.
    pub const POOL_RETIRED: &str = crate::methods::codes::TXPOOL_RETIRED;
    /// The node is starting.
    pub const STARTING: &str = "mine.starting";
    /// The node is stopping.
    pub const STOPPING: &str = "mine.stopping";
    /// The template could not be built.
    pub const UNBUILT: &str = "mine.unbuilt";
    /// The miner is already running, and it searches the height asked for.
    pub const RUNNING: &str = "mine.running";
    /// A miner is already running, and its bound does not search the height
    /// asked for.
    pub const BOUND_SHORT: &str = "mine.bound-short";
    /// The miner is not running.
    pub const STOPPED: &str = "mine.stopped";
    /// A one-permit host never mines.
    pub const ONE_PERMIT: &str = "mine.one-permit";
    /// A miner thread did not start.
    pub const THREAD: &str = "mine.thread";
    /// More threads than the host runs at once.
    pub const TOO_MANY_THREADS: &str = "mine.threads-over-host";
    /// The block is not hexadecimal, or does not parse.
    pub const BLOCK_MALFORMED: &str = "block.malformed";
    /// A consensus rule refused the block.
    pub const BLOCK_REFUSED: &str = "block.refused";
    /// The block lists bodies the pool does not show.
    pub const BLOCK_MISSING_BODIES: &str = "block.bodies-missing";
    /// The block's parent chain reaches no block this node holds.
    pub const BLOCK_UNLINKED: &str = "block.unlinked";
    /// This node holds the block already.
    pub const BLOCK_HELD_ALREADY: &str = "block.held-already";
    /// Stored as an alternative block; the tip did not change.
    pub const BLOCK_HELD: &str = "block.held";
    /// The block's fork is deeper than the reorganisation cap.
    pub const BLOCK_BEYOND_CAP: &str = "block.beyond-cap";
    /// The block extends a heavier chain this node cannot follow.
    pub const BLOCK_CANNOT_FOLLOW: &str = "block.heavier-unfollowed";
    /// The block is larger than any valid block near the tip.
    pub const BLOCK_OVERSIZE: &str = "block.oversize";
    /// `dev_block_generate` was asked for no blocks.
    pub const COUNT_ZERO: &str = "block.count-zero";
    /// `dev_block_generate` was asked for more blocks than this chain can
    /// grow by.
    pub const COUNT_OVERFLOW: &str = "block.count-overflow";
    /// `mine_start` was asked for zero threads.
    pub const THREADS_ZERO: &str = "mine.threads-zero";
    /// A pop would remove genesis or a block the undo journal retired.
    pub const POP_BELOW_FLOOR: &str = "chain.pop-below-floor";
}

fn hash_hex(hash: BlockHash) -> HashHex {
    HashHex::from_bytes(hash.to_bytes())
}

fn not_posted(why: Diagnostic) -> RpcError {
    RpcError::new(ErrorClass::NotReady, why)
}

fn amount(raw: u64) -> AtomicUnitsString {
    AtomicUnitsString::from(AtomicUnits::from_raw(raw))
}

/// `block_template`: the job the node posted, with its offsets and the
/// chain facts `block_template` carried (N2; IG-Q46). One posted job, one
/// chain state: every field is read from it.
///
/// # Errors
///
/// `NotReady` with the node's reason while no job is posted.
pub fn block_template(mining: &dyn MiningFacts) -> Result<block::BlockTemplate, RpcError> {
    let posted = mining.template()?.map_err(not_posted)?;
    Ok(block::BlockTemplate {
        difficulty: HexU128(posted.difficulty),
        height: Height(posted.height.to_raw()),
        extra_offset: Integer(posted.extra_nonce_offset),
        nonce_offset: Integer(posted.nonce_offset),
        reward: amount(posted.reward),
        parent: hash_hex(posted.prev_hash),
        seed_height: Height(posted.seed_height.to_raw()),
        body: Bytes(posted.block),
        hashing: Bytes(posted.hashing_blob),
        seed: hash_hex(posted.seed),
        seed_next: posted.next_seed.map(hash_hex).into(),
        version_major: Integer(u64::from(posted.major_version)),
        weight_median: Size(posted.median_weight),
        emission: amount(posted.already_generated),
    })
}

/// Run `f` over the mining handle on a blocking thread: the miner's start
/// spawns threads and its stop joins them, which may be mid-hash.
async fn on_a_blocking_thread<T: Send + 'static>(
    mining: &MiningHandle,
    f: impl FnOnce(&dyn MiningFacts) -> Result<T, FactsFault> + Send + 'static,
) -> Result<T, RpcError> {
    let mining = std::sync::Arc::clone(mining);
    tokio::task::spawn_blocking(move || f(&*mining))
        .await
        .map_err(|_| RpcError::from(FactsFault::Internal))?
        .map_err(RpcError::from)
}

/// `mine_start { threads }`: start the built-in miner on the node's job
/// board (`mine start [threads|auto]`); `auto` is the node's `mine-threads`.
/// It mines to the node's `mine-address` (IG-F23).
///
/// # Errors
///
/// `BadParams` for zero threads; `RefusedByMethod` with the node's
/// refusal: no address, already running, more threads than the host's
/// parallelism, a one-permit host, a thread that did not start, a stopped
/// node.
pub async fn mine_start(mining: &MiningHandle, request: node::MineStart) -> Result<Done, RpcError> {
    let threads = match request.threads {
        node::Threads::Auto(_) => None,
        node::Threads::Count(count) => Some(
            usize::try_from(count.0)
                .ok()
                .and_then(NonZeroUsize::new)
                .ok_or_else(|| {
                    RpcError::new(
                        ErrorClass::BadParams,
                        Diagnostic::new(
                            codes::THREADS_ZERO,
                            "threads is a count of at least one, or auto",
                        ),
                    )
                })?,
        ),
    };
    on_a_blocking_thread(mining, move |mining| mining.start(threads))
        .await?
        .map_err(|refused| RpcError::new(ErrorClass::RefusedByMethod, refused))?;
    Ok(Done)
}

/// `mine_stop`: stop the built-in miner. The node keeps running.
///
/// # Errors
///
/// `RefusedByMethod` when the miner was not running.
pub async fn mine_stop(mining: &MiningHandle) -> Result<Done, RpcError> {
    if !on_a_blocking_thread(mining, |mining| mining.stop()).await? {
        return Err(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(codes::STOPPED, "the miner is not running"),
        ));
    }
    Ok(Done)
}

/// `mine_status`: the miner, the posted job, and why none is posted
/// (IG-Q77). The job's fields are `null` while none is posted.
///
/// # Errors
///
/// The handle's fault.
pub fn mine_status(mining: &dyn MiningFacts) -> Result<node::MineStatus, RpcError> {
    let state = mining.status()?;
    Ok(node::MineStatus {
        active: state.miner.is_some(),
        speed: state.miner.map_or(
            node::MineSpeed {
                count: Count(0),
                window: Duration(0),
            },
            |miner| miner.speed,
        ),
        threads: Count(state.miner.map_or(0, |miner| u64::from(miner.threads))),
        address: state.address.map(Address).into(),
        block_spacing: Duration(shekyl_difficulty::T_SECONDS),
        height: state
            .posted
            .map(|posted| Height(posted.height.to_raw()))
            .into(),
        reward: state.posted.map(|posted| amount(posted.reward)).into(),
        difficulty: state.posted.map(|posted| HexU128(posted.difficulty)).into(),
        cause: state.absent.into(),
        txpool_retired: state.pool_retired,
    })
}

/// A block offered through the local-arrival entry that did not join the
/// chain, as the RW-Q3 class and diagnostic the caller is answered with.
fn not_joined(outcome: LocalOutcome) -> RpcError {
    let refused = |code: &str, message: &str| {
        RpcError::new(ErrorClass::RefusedByMethod, Diagnostic::new(code, message))
    };
    match outcome {
        LocalOutcome::Connected { .. } | LocalOutcome::Switched { .. } => {
            RpcError::from(FactsFault::Internal)
        }
        LocalOutcome::Refused { rule } => RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::BLOCK_REFUSED,
                format!("the block breaks consensus rule {rule}"),
            )
            .param("rule", rule),
        ),
        LocalOutcome::MissingBodies { indices } => {
            let listed = indices
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            RpcError::new(
                ErrorClass::RefusedByMethod,
                Diagnostic::new(
                    codes::BLOCK_MISSING_BODIES,
                    format!(
                        "the block lists transactions this node's pool does not hold, at indices {listed}"
                    ),
                )
                .param("indices", listed),
            )
        }
        LocalOutcome::Unlinked => refused(
            codes::BLOCK_UNLINKED,
            "the block's parent is not a block this node holds",
        ),
        LocalOutcome::AlreadyHeld => refused(
            codes::BLOCK_HELD_ALREADY,
            "this node holds the block already",
        ),
        LocalOutcome::Held => refused(
            codes::BLOCK_HELD,
            "the block was stored as an alternative; the tip did not change",
        ),
        LocalOutcome::BeyondCap => refused(
            codes::BLOCK_BEYOND_CAP,
            "the block's fork is deeper than this node reorganises",
        ),
        LocalOutcome::CannotFollow => refused(
            codes::BLOCK_CANNOT_FOLLOW,
            "the block extends a heavier chain this node cannot follow",
        ),
        LocalOutcome::Oversize => refused(
            codes::BLOCK_OVERSIZE,
            "the block is larger than any valid block near the tip",
        ),
        LocalOutcome::Stopped => RpcError::new(
            ErrorClass::NotReady,
            Diagnostic::new(
                codes::STOPPING,
                "the node is stopping; the block was not taken",
            ),
        ),
    }
}

/// `block_submit { body }`: a block, through the node's local-arrival
/// entry (b4). Its listed bodies come from the pool. It succeeds when the
/// block connects, or when it is the new tip after a switch.
///
/// # Errors
///
/// `BadParams` for a body that is not a block; otherwise the outcome's
/// class and diagnostic: `MissingBodies` names the indices.
pub async fn block_submit(
    door: &dyn DoorFacts,
    request: block::BlockBody,
) -> Result<block::BlockId, RpcError> {
    let bytes = request.body.into_vec();
    let parsed = shekyl_wire::Block::from_bytes(&bytes).map_err(|e| {
        RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(
                codes::BLOCK_MALFORMED,
                format!("the bytes are not a block: {e}"),
            ),
        )
    })?;
    let hash = parsed.hash();
    match door.offer_local(bytes).await? {
        LocalOutcome::Connected { .. } | LocalOutcome::Switched { .. } => Ok(block::BlockId {
            hash: hash_hex(hash),
        }),
        other => Err(not_joined(other)),
    }
}

/// Stops, on drop, a miner `dev_block_generate` started: a caller that goes
/// away mid-wait leaves no miner running. It is built inside the blocking
/// start, so a caller that goes away while that start is still joining
/// drops this when the start finishes, and the miner the start goes on to
/// spawn is stopped. The stop can wait out one earlier hash on the join
/// gate, so on a runtime it runs on a blocking thread, and the wait is
/// detached: the gate, not this caller, joins.
struct StartedMiner(Option<MiningHandle>);

impl StartedMiner {
    /// Stop the miner now, on a blocking thread, and disarm the guard.
    async fn stop(mut self) -> Result<(), RpcError> {
        match self.0.take() {
            Some(mining) => on_a_blocking_thread(&mining, |mining| mining.stop().map(drop)).await,
            None => Ok(()),
        }
    }
}

impl Drop for StartedMiner {
    fn drop(&mut self) {
        let Some(mining) = self.0.take() else {
            return;
        };
        let stop = move || {
            if let Err(fault) = mining.stop() {
                tracing::error!("dev_block_generate: the miner it started did not stop: {fault:?}");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(stop)),
            Err(_) => stop(),
        }
    }
}

/// `dev_block_generate { count }`, an armed lever (b6): start the built-in
/// miner if it is stopped, wait until the tip is `count` blocks higher,
/// and stop the miner if this call started it — on return, and when the
/// call is dropped mid-wait. The blocks are the node's own template's,
/// paying its `mine-address` (N2).
///
/// **Exactly `count` blocks when this call starts the miner.** It starts
/// that miner with [`MiningFacts::start_until`] at the target height, so
/// no worker searches a job above it, and the block a worker could
/// otherwise find between the target connecting and the stop does not
/// exist. A miner already running is left running. When it searches a job
/// at the target — `mine_start`, or a bound at least that high — this
/// call waits and does not stop it: the tip is then at least `count`
/// higher, and the reply's `height` says where it is. When that miner's
/// bound stops short of the target, the call is refused
/// ([`codes::BOUND_SHORT`]) and waits for nothing.
///
/// It is refused at once while [`MiningFacts::refusal`] is `Some` (not
/// synced, no address, the pool retired, a build that stayed withdrawn),
/// and the wait ends when it becomes so: no miner can move the tip without
/// a job. A posted job, and a withdrawal the next pass replaces, is waited
/// out, before the wait as during it ([`MiningFacts::withdrawn`]).
///
/// # Errors
///
/// `BadParams` for a count of zero; `NotReady` with the node's reason when
/// [`MiningFacts::refusal`] is `Some`, before the wait, or during it with the
/// tip short of the target at the stop; the miner's refusal; `NotReady`
/// when the node stops first. A withdrawal that comes with the block
/// reaching the target is not an error: the chain at the stop decides, so a
/// caller that retries on an error does not mine past its count.
pub async fn dev_block_generate(
    mining: &MiningHandle,
    door: &dyn DoorFacts,
    chain: &dyn ChainFacts,
    _armed: Armed,
    request: block::GenerateCount,
) -> Result<block::Generated, RpcError> {
    let count = request.count.0;
    if count == 0 {
        return Err(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::COUNT_ZERO, "count must be at least one"),
        ));
    }
    // A refusal already posted is no reason to start a miner. A posted
    // job, and a withdrawal the next pass replaces, are waited out below.
    if let Some(why) = mining.refusal().map_err(RpcError::from)? {
        return Err(RpcError::new(ErrorClass::NotReady, why));
    }
    let start = chain.chain_tip()?.chain_height;
    let wanted = BlockCount::from_raw(count);
    let Some(target) = start.checked_add(wanted).and_then(ChainCount::tip) else {
        return Err(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::COUNT_OVERFLOW, "count does not fit on this chain")
                .param("count", count.to_string())
                .param("chain_height", start.to_raw().to_string()),
        ));
    };
    // The guard is the blocking task's value. Dropping this call while
    // `start_until` is still joining detaches that task; when it then
    // spawns a miner, dropping the value stops it. A guard built after
    // this await would never exist.
    let started = {
        let guard_mining = std::sync::Arc::clone(mining);
        match on_a_blocking_thread(mining, move |facts| {
            // `mine.running` covers the target, so wait and leave that
            // miner running. Any other refusal, `mine.bound_short`
            // included, is returned: waiting would not move the tip.
            Ok(match facts.start_until(target)? {
                Ok(()) => Ok(StartedMiner(Some(guard_mining))),
                Err(running) if running.code == codes::RUNNING => Ok(StartedMiner(None)),
                Err(refused) => Err(refused),
            })
        })
        .await?
        {
            Ok(guard) => guard,
            Err(refused) => return Err(RpcError::new(ErrorClass::RefusedByMethod, refused)),
        }
    };
    let reached = tokio::select! {
        reached = door.tip_at_least(target) => reached.map_err(RpcError::from),
        lost = mining.withdrawn() => Err(match lost {
            Ok(why) => RpcError::new(ErrorClass::NotReady, why),
            Err(fault) => RpcError::from(fault),
        }),
    };
    started.stop().await?;
    let end = chain.chain_tip()?.chain_height;
    // The race above has two winners when the pass that connects the target
    // block also withdraws the job, and either can be polled first. The
    // chain says which happened (the regtest sync rig mined 102 blocks for
    // 101 when its retry read a won race as a failure).
    if let Err(lost) = reached {
        if end.tip().is_none_or(|tip| tip < target) {
            return Err(lost);
        }
    }
    let mut blocks = Vec::new();
    for height in start.next_height().ordinals_until(end.next_height()) {
        if let Some(hash) = chain.block_hash_at(height)?.hash {
            blocks.push(hash_hex(hash));
        }
    }
    Ok(block::Generated {
        height: Height(end.tip().map_or(0, shekyl_types::BlockHeight::to_raw)),
        hash: blocks,
    })
}

/// `dev_chain_pop { count }`, an armed lever (DX-Q3, Q7): pop that many
/// blocks from the tip; their transactions return to the pool. The reply is
/// the new tip's height (IG-Q45).
///
/// # Errors
///
/// `RefusedByMethod` when the pop would remove genesis or a block the undo
/// journal retired; nothing was popped, and the node is up.
pub async fn dev_chain_pop(
    door: &dyn DoorFacts,
    _armed: Armed,
    request: block::PopCount,
) -> Result<block::Popped, RpcError> {
    let count = request.count.0;
    match door.pop(count).await? {
        PopOutcome::Popped { tip } => Ok(block::Popped {
            height: Height(tip.to_raw()),
        }),
        PopOutcome::Refused { tip, floor } => Err(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::POP_BELOW_FLOOR,
                format!(
                    "popping {} blocks from tip {} would remove a block below the lowest poppable height, {}",
                    count,
                    tip.to_raw(),
                    floor.to_raw()
                ),
            )
            .param("tip", tip.to_raw().to_string())
            .param("floor", floor.to_raw().to_string()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::Handles;
    use shekyl_rpc_types::method::{admit_armed, Row};
    use shekyl_rpc_types::wire;

    /// `dev_block_generate`'s armed admission, as the dispatcher grants it.
    fn armed() -> Armed {
        admit_armed(&Row::of::<wire::DevBlockGenerate>(), true).expect("armed")
    }

    fn count(n: u64) -> block::GenerateCount {
        block::GenerateCount { count: Count(n) }
    }

    /// An absent node is not ready, never an empty or zero answer
    /// (RK-D23), on every mining method.
    #[tokio::test]
    async fn an_absent_node_is_not_ready_on_every_mining_method() {
        let handles = Handles::absent();
        let class = |error: RpcError| error.class;
        assert_eq!(
            block_template(&*handles.mining).map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            mine_status(&*handles.mining).map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            mine_stop(&handles.mining).await.map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            mine_start(
                &handles.mining,
                node::MineStart {
                    threads: node::Threads::Count(Count(1)),
                }
            )
            .await
            .map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            handles
                .mining
                .refusal()
                .map_err(RpcError::from)
                .map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            handles
                .mining
                .withdrawn()
                .await
                .map_err(RpcError::from)
                .map_err(class),
            Err(ErrorClass::NotReady)
        );
    }

    /// A node between states: its job is withdrawn as starting, a reason
    /// the next tip clears, so `withdrawn` never resolves; the tip the
    /// call waits for is already reached.
    struct Starting {
        stops: std::sync::atomic::AtomicUsize,
        /// Heights [`MiningFacts::start_until`] was called with, in order.
        until: std::sync::Mutex<Vec<shekyl_types::BlockHeight>>,
    }

    impl Starting {
        fn new() -> Self {
            Self {
                stops: std::sync::atomic::AtomicUsize::new(0),
                until: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl MiningFacts for Starting {
        fn running(&self) -> Result<bool, FactsFault> {
            Ok(false)
        }
        fn template(
            &self,
        ) -> Result<Result<crate::mining_facts::PostedTemplate, Diagnostic>, FactsFault> {
            Ok(Err(Diagnostic::new(
                codes::STARTING,
                "the node is starting",
            )))
        }
        fn start(
            &self,
            _threads: Option<NonZeroUsize>,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            Ok(Ok(()))
        }
        fn start_until(
            &self,
            height: shekyl_types::BlockHeight,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            self.until.lock().expect("until").push(height);
            Ok(Ok(()))
        }
        fn stop(&self) -> Result<bool, FactsFault> {
            self.stops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            unreachable!("dev_block_generate reads no status")
        }
        fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
            Ok(None)
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            Box::pin(std::future::pending())
        }
    }

    struct Reached;

    impl DoorFacts for Reached {
        fn room(&self) -> Result<usize, FactsFault> {
            unreachable!("dev_block_generate takes no room")
        }
        fn offer_local(&self, _block: Vec<u8>) -> crate::mining_facts::Pending<'_, LocalOutcome> {
            unreachable!("dev_block_generate offers nothing")
        }
        fn pop(&self, _count: u64) -> crate::mining_facts::Pending<'_, PopOutcome> {
            unreachable!("dev_block_generate pops nothing")
        }
        fn tip_at_least(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> crate::mining_facts::Pending<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A chain at genesis.
    struct Genesis;

    impl ChainFacts for Genesis {
        fn chain_tip(&self) -> Result<crate::chain_facts::ChainTip, FactsFault> {
            Ok(crate::chain_facts::ChainTip {
                chain_height: ChainCount::from_raw(1),
                top_hash: BlockHash::from_bytes([1; 32]),
                target_height: None,
                synchronized: true,
                release_build: false,
                halt: None,
            })
        }
        fn identity(&self) -> Result<crate::chain_facts::DaemonIdentity, FactsFault> {
            unreachable!("dev_block_generate reads no identity")
        }
        fn block_hash_at(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<crate::chain_facts::BlockHashAt, FactsFault> {
            Ok(crate::chain_facts::BlockHashAt {
                hash: Some(BlockHash::from_bytes([2; 32])),
                chain_height: ChainCount::from_raw(2),
            })
        }
        fn block_header_at(
            &self,
            _at: crate::chain_facts::BlockLookup,
            _fill_pow_hash: bool,
        ) -> Result<crate::chain_facts::BlockHeaderAt, FactsFault> {
            unreachable!("dev_block_generate reads no header")
        }
        fn fee_estimate(&self) -> Result<crate::chain_facts::FeeEstimate, FactsFault> {
            unreachable!("dev_block_generate reads no fee")
        }
        fn block_at(
            &self,
            _at: crate::chain_facts::BlockLookup,
            _fill_pow_hash: bool,
        ) -> Result<crate::chain_facts::BlockAt, FactsFault> {
            unreachable!("dev_block_generate reads no block")
        }
    }

    /// `dev_block_generate` on a node whose job is withdrawn for a reason that
    /// clears itself (starting, or between two tips) waits it out instead
    /// of refusing, and stops the miner it started (the landing review of
    /// #1165, N4). Red edit: refuse whenever no job is posted.
    #[tokio::test]
    async fn generateblocks_waits_out_a_reason_that_clears_itself() {
        let mining: MiningHandle = std::sync::Arc::new(Starting::new());
        let generated = dev_block_generate(&mining, &Reached, &Genesis, armed(), count(1))
            .await
            .expect("waited out, not refused");
        // The double's chain holds genesis alone, so the tip is 0.
        assert_eq!(generated.height, Height(0));
    }

    /// A node whose job is withdrawn for good the moment the call waits: a
    /// refusal the call does not wait out (not synced).
    struct WithdrawnAtOnce;

    impl MiningFacts for WithdrawnAtOnce {
        fn running(&self) -> Result<bool, FactsFault> {
            Ok(false)
        }
        fn template(
            &self,
        ) -> Result<Result<crate::mining_facts::PostedTemplate, Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate reads no template")
        }
        fn start(
            &self,
            _threads: Option<NonZeroUsize>,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate bounds the miner it starts")
        }
        fn start_until(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            Ok(Ok(()))
        }
        fn stop(&self) -> Result<bool, FactsFault> {
            Ok(true)
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            unreachable!("dev_block_generate reads no status")
        }
        fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
            Ok(None)
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            Box::pin(async { Ok(Diagnostic::new(codes::SYNCING, "the node is not synced")) })
        }
    }

    /// A door whose tip wait has not woken.
    struct Unwoken;

    impl DoorFacts for Unwoken {
        fn room(&self) -> Result<usize, FactsFault> {
            unreachable!("dev_block_generate takes no room")
        }
        fn offer_local(&self, _block: Vec<u8>) -> crate::mining_facts::Pending<'_, LocalOutcome> {
            unreachable!("dev_block_generate offers nothing")
        }
        fn pop(&self, _count: u64) -> crate::mining_facts::Pending<'_, PopOutcome> {
            unreachable!("dev_block_generate pops nothing")
        }
        fn tip_at_least(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> crate::mining_facts::Pending<'_, ()> {
            Box::pin(std::future::pending())
        }
    }

    /// A chain of one block at the start's read, and `after` blocks at
    /// every read after it: the stop's.
    struct Grows {
        reads: std::sync::atomic::AtomicUsize,
        after: u64,
    }

    impl Grows {
        fn to(after: u64) -> Self {
            Self {
                reads: std::sync::atomic::AtomicUsize::new(0),
                after,
            }
        }
    }

    impl ChainFacts for Grows {
        fn chain_tip(&self) -> Result<crate::chain_facts::ChainTip, FactsFault> {
            let read = self
                .reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(crate::chain_facts::ChainTip {
                chain_height: ChainCount::from_raw(if read == 0 { 1 } else { self.after }),
                top_hash: BlockHash::from_bytes([1; 32]),
                target_height: None,
                synchronized: true,
                release_build: false,
                halt: None,
            })
        }
        fn identity(&self) -> Result<crate::chain_facts::DaemonIdentity, FactsFault> {
            unreachable!("dev_block_generate reads no identity")
        }
        fn block_hash_at(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<crate::chain_facts::BlockHashAt, FactsFault> {
            Ok(crate::chain_facts::BlockHashAt {
                hash: Some(BlockHash::from_bytes([2; 32])),
                chain_height: ChainCount::from_raw(self.after),
            })
        }
        fn block_header_at(
            &self,
            _at: crate::chain_facts::BlockLookup,
            _fill_pow_hash: bool,
        ) -> Result<crate::chain_facts::BlockHeaderAt, FactsFault> {
            unreachable!("dev_block_generate reads no header")
        }
        fn fee_estimate(&self) -> Result<crate::chain_facts::FeeEstimate, FactsFault> {
            unreachable!("dev_block_generate reads no fee")
        }
        fn block_at(
            &self,
            _at: crate::chain_facts::BlockLookup,
            _fill_pow_hash: bool,
        ) -> Result<crate::chain_facts::BlockAt, FactsFault> {
            unreachable!("dev_block_generate reads no block")
        }
    }

    /// **The chain at the stop decides.** The job is withdrawn as the
    /// target block connects, and the withdrawal is polled first: the block
    /// is there, so the call succeeds with it, and a caller that retries on
    /// an error does not mine one more (CI on #1340: the regtest sync rig's
    /// source reached 102 blocks for 101). A withdrawal with the tip short of
    /// the target is still refused. Red edit: return the race's error
    /// whatever the chain reads.
    #[tokio::test]
    async fn generateblocks_reads_the_chain_when_a_withdrawal_wins_the_race() {
        let mining: MiningHandle = std::sync::Arc::new(WithdrawnAtOnce);
        let generated = dev_block_generate(&mining, &Unwoken, &Grows::to(2), armed(), count(1))
            .await
            .expect("the block connected");
        assert_eq!(generated.height, Height(1), "the new tip, an ordinal");
        assert_eq!(generated.hash.len(), 1);
        let refused = dev_block_generate(&mining, &Unwoken, &Grows::to(1), armed(), count(1))
            .await
            .expect_err("no block connected");
        assert_eq!(refused.class, ErrorClass::NotReady);
    }

    /// The miner `dev_block_generate` starts searches no block above the target.
    /// On a chain of one block, `count` 3 calls [`MiningFacts::start_until`]
    /// once, at height 3, the tip the call waits for. That bound is what
    /// makes the count exact (`SearchBound::Until`); an unbounded start can
    /// land one block past the target before the stop. Red edit: call
    /// `start` instead of `start_until`.
    #[tokio::test]
    async fn generateblocks_starts_its_miner_until_the_target() {
        let starting = std::sync::Arc::new(Starting::new());
        let mining: MiningHandle = starting.clone();
        dev_block_generate(&mining, &Reached, &Genesis, armed(), count(3))
            .await
            .expect("generated");
        assert_eq!(
            *starting.until.lock().expect("until"),
            vec![shekyl_types::BlockHeight::from_raw(3)],
            "start_until once, at the target tip"
        );
    }

    /// `start_until` answers `mine.bound_short`: the miner already running
    /// cannot reach the target.
    struct ShortOfTarget;

    impl MiningFacts for ShortOfTarget {
        fn running(&self) -> Result<bool, FactsFault> {
            Ok(true)
        }
        fn template(
            &self,
        ) -> Result<Result<crate::mining_facts::PostedTemplate, Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate reads no template before it starts")
        }
        fn start(
            &self,
            _threads: Option<NonZeroUsize>,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate bounds the miner it starts")
        }
        fn start_until(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            Ok(Err(Diagnostic::new(
                codes::BOUND_SHORT,
                "the miner already running searches no job above height 1, which does not reach height 2",
            )))
        }
        fn stop(&self) -> Result<bool, FactsFault> {
            unreachable!("a refused start stops nothing")
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            unreachable!("dev_block_generate reads no status")
        }
        fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
            Ok(None)
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            unreachable!("a short bound is refused before the wait")
        }
    }

    /// A door whose tip wait must not be polled: the short refusal returns
    /// first.
    struct Unreached;

    impl DoorFacts for Unreached {
        fn room(&self) -> Result<usize, FactsFault> {
            unreachable!("dev_block_generate takes no room")
        }
        fn offer_local(&self, _block: Vec<u8>) -> crate::mining_facts::Pending<'_, LocalOutcome> {
            unreachable!("dev_block_generate offers nothing")
        }
        fn pop(&self, _count: u64) -> crate::mining_facts::Pending<'_, PopOutcome> {
            unreachable!("dev_block_generate pops nothing")
        }
        fn tip_at_least(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> crate::mining_facts::Pending<'_, ()> {
            unreachable!("a short bound is refused before the wait")
        }
    }

    /// The refusal is returned, and the tip is not waited on: that wait
    /// would not end. Red edit: treat `mine.bound_short` as `mine.running`.
    #[tokio::test]
    async fn generateblocks_refuses_a_miner_bound_short_of_the_target() {
        let mining: MiningHandle = std::sync::Arc::new(ShortOfTarget);
        let refused = dev_block_generate(&mining, &Unreached, &Genesis, armed(), count(1))
            .await
            .expect_err("a miner that cannot reach the target is refused");
        assert_eq!(refused.class, ErrorClass::RefusedByMethod);
        assert_eq!(refused.diagnostic.code, codes::BOUND_SHORT);
    }

    /// `start_until` blocks until released. Dropping `dev_block_generate` while
    /// it is there detaches the blocking task; the guard has to be that
    /// task's value, or the miner it goes on to start is never stopped.
    struct HoldStart {
        entered: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        release: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        stops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MiningFacts for HoldStart {
        fn running(&self) -> Result<bool, FactsFault> {
            Ok(false)
        }
        fn template(
            &self,
        ) -> Result<Result<crate::mining_facts::PostedTemplate, Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate reads no template before it starts")
        }
        fn start(
            &self,
            _threads: Option<NonZeroUsize>,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            unreachable!("dev_block_generate bounds the miner it starts")
        }
        fn start_until(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            let (lock, cv) = &*self.entered;
            *lock.lock().expect("entered") = true;
            cv.notify_all();
            let (lock, cv) = &*self.release;
            let mut released = lock.lock().expect("release");
            while !*released {
                released = cv.wait(released).expect("release");
            }
            Ok(Ok(()))
        }
        fn stop(&self) -> Result<bool, FactsFault> {
            self.stops
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            Ok(true)
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            unreachable!("dev_block_generate reads no status")
        }
        fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
            Ok(None)
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            Box::pin(std::future::pending())
        }
    }

    /// Dropping `dev_block_generate` while its start is still blocked stops the
    /// miner that start goes on to spawn. Red edit: build `StartedMiner`
    /// after `on_a_blocking_thread` returns.
    #[tokio::test]
    async fn dropping_generateblocks_while_start_is_blocked_stops_the_miner() {
        let entered =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let release =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let stops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mining: MiningHandle = std::sync::Arc::new(HoldStart {
            entered: std::sync::Arc::clone(&entered),
            release: std::sync::Arc::clone(&release),
            stops: std::sync::Arc::clone(&stops),
        });
        let call = tokio::spawn({
            let mining = std::sync::Arc::clone(&mining);
            async move { dev_block_generate(&mining, &Reached, &Genesis, armed(), count(1)).await }
        });
        let entered_wait = std::sync::Arc::clone(&entered);
        tokio::task::spawn_blocking(move || {
            let (lock, cv) = &*entered_wait;
            let mut guard = lock.lock().expect("entered");
            while !*guard {
                guard = cv.wait(guard).expect("entered");
            }
        })
        .await
        .expect("the wait");
        call.abort();
        assert!(
            call.await.is_err(),
            "the call was dropped while start was blocked"
        );
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release") = true;
            cv.notify_all();
        }
        let started = std::time::Instant::now();
        while stops.load(std::sync::atomic::Ordering::Acquire) == 0 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the detached start was not stopped"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A miner's speed, or none when the miner is stopped.
    struct Reported {
        speed: Option<node::MineSpeed>,
    }

    impl MiningFacts for Reported {
        fn running(&self) -> Result<bool, FactsFault> {
            Ok(self.speed.is_some())
        }
        fn template(
            &self,
        ) -> Result<Result<crate::mining_facts::PostedTemplate, Diagnostic>, FactsFault> {
            unreachable!("this status reads no template")
        }
        fn start(
            &self,
            _threads: Option<NonZeroUsize>,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            unreachable!("this status starts nothing")
        }
        fn start_until(
            &self,
            _height: shekyl_types::BlockHeight,
        ) -> Result<Result<(), Diagnostic>, FactsFault> {
            unreachable!("this status starts nothing")
        }
        fn stop(&self) -> Result<bool, FactsFault> {
            unreachable!("this status stops nothing")
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            Ok(crate::mining_facts::MiningState {
                miner: self
                    .speed
                    .map(|speed| crate::mining_facts::MinerState { threads: 1, speed }),
                address: None,
                posted: None,
                pool_retired: false,
                absent: None,
            })
        }
        fn refusal(&self) -> Result<Option<Diagnostic>, FactsFault> {
            Ok(None)
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            Box::pin(std::future::pending())
        }
    }

    /// Eight hashes in ten seconds is 0.8 H/s: the reply carries the count
    /// and the window, never a rounded rate. A stopped miner reports no
    /// hashes and no threads.
    #[test]
    fn a_miner_below_one_hash_a_second_reports_its_count_and_window() {
        let speed = node::MineSpeed {
            count: Count(8),
            window: Duration(10),
        };
        let response = mine_status(&Reported { speed: Some(speed) }).expect("status");
        assert!(response.active);
        assert_eq!(response.threads, Count(1));
        assert_eq!(response.speed, speed);
        let wire = serde_json::to_value(&response).expect("json");
        assert_eq!(wire["speed"]["count"], 8);
        assert_eq!(wire["speed"]["window"], 10);

        let stopped = mine_status(&Reported { speed: None }).expect("status");
        assert!(!stopped.active);
        assert_eq!(stopped.speed.count, Count(0));
        assert_eq!(stopped.threads, Count(0));
    }

    /// Zero threads is the caller's error, `mine.threads-zero` (BadParams),
    /// refused before the node is touched. Red edit: start with no bound.
    #[tokio::test]
    async fn zero_threads_is_refused_before_the_node_is_touched() {
        let handles = Handles::absent();
        let refused = mine_start(
            &handles.mining,
            node::MineStart {
                threads: node::Threads::Count(Count(0)),
            },
        )
        .await
        .expect_err("zero threads");
        assert_eq!(refused.class, ErrorClass::BadParams);
        assert_eq!(refused.diagnostic.code, codes::THREADS_ZERO);
    }

    /// A zero count is `block.count-zero` (BadParams), before the miner's
    /// refusal is read, so the answer is the same on any node.
    #[tokio::test]
    async fn a_zero_count_is_refused_before_anything_is_read() {
        let mining: MiningHandle = std::sync::Arc::new(Starting::new());
        let refused = dev_block_generate(&mining, &Unreached, &Genesis, armed(), count(0))
            .await
            .expect_err("a zero count");
        assert_eq!(refused.class, ErrorClass::BadParams);
        assert_eq!(refused.diagnostic.code, codes::COUNT_ZERO);
    }
}
