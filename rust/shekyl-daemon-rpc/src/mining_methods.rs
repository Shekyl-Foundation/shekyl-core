// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The mining methods (`DRS_X_STORE_FLIP.md` DX-Q3, b3), over the node's
//! [`MiningFacts`] and [`DoorFacts`]. **Built and not routed:** the server
//! answers each from the C++ table until the flip, which points dispatch
//! here. Each failure is an RW-Q3 class with a typed diagnostic
//! ([`codes`]).
//!
//! `get_block_template` and `get_miner_data` read the job the node posted;
//! they build nothing (N2). The methods that wait or join are `async`:
//! `submit_block` and `generateblocks` wait on the node, and `start_mining`,
//! `stop_mining` and `generateblocks` run the miner's start and stop, which
//! spawn and join threads, on a blocking thread of their own. Every other
//! read is short.

use std::num::NonZeroUsize;

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::methods::Method;
use shekyl_rpc_types::mining::{
    GenerateBlocksRequest, GenerateBlocksResponse, GetBlockTemplateResponse, GetMinerDataResponse,
    MinerThreads, MiningStatusResponse, PopBlocksRequest, PopBlocksResponse, StartMiningRequest,
    StatusOnlyResponse, SubmitBlockRequest, SubmitBlockResponse, TxBacklogEntry,
};
use shekyl_rpc_types::{HashHex, RpcStatus};
use shekyl_types::{BlockCount, BlockHash, ChainCount};

use crate::chain_facts::{ChainFacts, FactsFault};
use crate::handles::{DoorFacts, MiningFacts, MiningHandle};
use crate::methods::split_128;
use crate::mining_facts::{LocalOutcome, PopOutcome};

/// The mining methods' diagnostic codes, each stated once.
pub mod codes {
    /// The node cannot answer yet.
    pub const NOT_READY: &str = "node.not_ready";
    /// The node's store faulted.
    pub const STORE: &str = "node.store";
    /// A defect in the node.
    pub const INTERNAL: &str = "node.internal";
    /// No `mine-address` row.
    pub const NO_ADDRESS: &str = "mine.no_address";
    /// Chain sync does not say the node is synced.
    pub const NOT_SYNCED: &str = "mine.not_synced";
    /// The pool file faulted.
    pub const POOL_RETIRED: &str = "mine.pool_retired";
    /// The node is starting.
    pub const STARTING: &str = "mine.starting";
    /// The node is stopping.
    pub const STOPPING: &str = "mine.stopping";
    /// The template could not be built.
    pub const UNBUILT: &str = "mine.unbuilt";
    /// The miner is already running.
    pub const RUNNING: &str = "mine.running";
    /// The miner is not running.
    pub const STOPPED: &str = "mine.stopped";
    /// A one-permit host never mines.
    pub const ONE_PERMIT: &str = "mine.one_permit";
    /// A miner thread did not start.
    pub const THREAD: &str = "mine.thread";
    /// More threads than the host runs at once.
    pub const TOO_MANY_THREADS: &str = "mine.too_many_threads";
    /// The block is not hexadecimal, or does not parse.
    pub const BLOCK_MALFORMED: &str = "block.malformed";
    /// A consensus rule refused the block.
    pub const BLOCK_REFUSED: &str = "block.refused";
    /// The block lists bodies the pool does not show.
    pub const BLOCK_MISSING_BODIES: &str = "block.missing_bodies";
    /// The block's parent chain reaches no block this node holds.
    pub const BLOCK_UNLINKED: &str = "block.unlinked";
    /// This node holds the block already.
    pub const BLOCK_HELD_ALREADY: &str = "block.held_already";
    /// Stored as an alternative block; the tip did not change.
    pub const BLOCK_HELD: &str = "block.held";
    /// The block's fork is deeper than the reorganisation cap.
    pub const BLOCK_BEYOND_CAP: &str = "block.beyond_cap";
    /// The block extends a heavier chain this node cannot follow.
    pub const BLOCK_CANNOT_FOLLOW: &str = "block.cannot_follow";
    /// The block is larger than any valid block near the tip.
    pub const BLOCK_OVERSIZE: &str = "block.oversize";
    /// `generateblocks` was asked for no blocks.
    pub const COUNT_ZERO: &str = "block.count_zero";
    /// `generateblocks` was asked for more blocks than this chain can grow by.
    pub const COUNT_OVERFLOW: &str = "block.count_overflow";
    /// An armed lever, and the node was not started armed.
    pub const UNARMED: &str = "rpc.unarmed";
    /// A pop would remove genesis or a block the undo journal retired.
    pub const POP_BELOW_FLOOR: &str = "chain.pop_below_floor";
}

/// The RandomX algorithm name `mining_status` reports.
const POW_ALGORITHM: &str = "RandomX";

/// Proof that an armed lever's row was checked against the node's
/// armed-lever switch (RW-Q7's `armed` column; DX-Q3, Q8). Only
/// [`admit_armed`] makes one, so an armed handler cannot run unchecked.
#[derive(Debug)]
pub struct Armed(());

/// Admit a call of `row` under the armed-lever switch: a row that is not
/// armed always passes; an armed row passes only when the node was
/// started with the switch on.
///
/// # Errors
///
/// [`ErrorClass::OutsideTheGrant`], whatever the caller's grant.
pub fn admit_armed(row: &Method, switch_on: bool) -> Result<Armed, RpcError> {
    if row.armed && !switch_on {
        return Err(RpcError::new(
            ErrorClass::OutsideTheGrant,
            Diagnostic::new(
                codes::UNARMED,
                format!(
                    "{} is an armed test lever; start the node with dev-rpc to serve it",
                    row.name
                ),
            )
            .param("method", row.name),
        ));
    }
    Ok(Armed(()))
}

impl From<FactsFault> for RpcError {
    fn from(fault: FactsFault) -> Self {
        match fault {
            FactsFault::NotReady | FactsFault::NullHandle | FactsFault::HubAbsent => Self::new(
                ErrorClass::NotReady,
                Diagnostic::new(codes::NOT_READY, "the node is not ready; ask again later"),
            ),
            FactsFault::Inconsistent | FactsFault::StoreUnreadable => Self::new(
                ErrorClass::StoreFault,
                Diagnostic::new(codes::STORE, "the node's store faulted while answering"),
            ),
            FactsFault::Internal | FactsFault::Unknown(_) => Self::new(
                ErrorClass::Internal,
                Diagnostic::new(codes::INTERNAL, "the node failed while answering"),
            ),
        }
    }
}

fn hash_hex(hash: BlockHash) -> HashHex {
    HashHex::from_bytes(hash.to_bytes())
}

fn not_posted(why: Diagnostic) -> RpcError {
    RpcError::new(ErrorClass::NotReady, why)
}

/// `get_block_template`: the job the node posted, and its offsets (N2).
///
/// # Errors
///
/// `NotReady` with the node's reason while no job is posted.
pub fn get_block_template(mining: &dyn MiningFacts) -> Result<GetBlockTemplateResponse, RpcError> {
    let posted = mining.template()?.map_err(not_posted)?;
    let (difficulty, wide_difficulty, difficulty_top64) = split_128(posted.difficulty);
    Ok(GetBlockTemplateResponse {
        status: RpcStatus::ok(),
        difficulty,
        wide_difficulty,
        difficulty_top64,
        height: posted.height.to_raw(),
        reserved_offset: posted.extra_nonce_offset,
        nonce_offset: posted.nonce_offset,
        expected_reward: posted.reward,
        prev_hash: hash_hex(posted.prev_hash),
        seed_height: posted.seed_height.to_raw(),
        seed_hash: hash_hex(posted.seed),
        next_seed_hash: posted
            .next_seed
            .map_or_else(String::new, |next| hex::encode(next.to_bytes())),
        blocktemplate_blob: hex::encode(&posted.block),
        blockhashing_blob: hex::encode(&posted.hashing_blob),
    })
}

/// `get_miner_data`: the posted job's chain facts and listed bodies.
///
/// # Errors
///
/// `NotReady` with the node's reason while no job is posted.
pub fn get_miner_data(mining: &dyn MiningFacts) -> Result<GetMinerDataResponse, RpcError> {
    let posted = mining.template()?.map_err(not_posted)?;
    Ok(GetMinerDataResponse {
        status: RpcStatus::ok(),
        major_version: posted.major_version,
        height: posted.height.to_raw(),
        prev_id: hash_hex(posted.prev_hash),
        seed_hash: hash_hex(posted.seed),
        difficulty: format!("0x{:x}", posted.difficulty),
        median_weight: posted.median_weight,
        already_generated_coins: posted.already_generated,
        tx_backlog: posted
            .backlog
            .iter()
            .map(|entry| TxBacklogEntry {
                id: HashHex::from_bytes(entry.id.to_bytes()),
                weight: entry.weight,
                fee: entry.fee,
            })
            .collect(),
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

/// `start_mining { threads }`: start the built-in miner on the node's job
/// board (`mine start [threads|auto]`); `auto` is the host's parallelism.
///
/// # Errors
///
/// `RefusedByMethod` with the node's refusal: no address, already
/// running, more threads than the host's parallelism, a one-permit host, a
/// thread that did not start, a stopped node.
pub async fn start_mining(
    mining: &MiningHandle,
    request: StartMiningRequest,
) -> Result<StatusOnlyResponse, RpcError> {
    let threads = match request.threads {
        MinerThreads::Auto => None,
        MinerThreads::Count(count) => {
            Some(NonZeroUsize::try_from(count).map_err(|_| RpcError::from(FactsFault::Internal))?)
        }
    };
    on_a_blocking_thread(mining, move |mining| mining.start(threads))
        .await?
        .map_err(|refused| RpcError::new(ErrorClass::RefusedByMethod, refused))?;
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

/// `stop_mining`: stop the built-in miner. The node keeps running.
///
/// # Errors
///
/// `RefusedByMethod` when the miner was not running.
pub async fn stop_mining(mining: &MiningHandle) -> Result<StatusOnlyResponse, RpcError> {
    if !on_a_blocking_thread(mining, |mining| mining.stop()).await? {
        return Err(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(codes::STOPPED, "the miner is not running"),
        ));
    }
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

/// `mining_status`: the miner, the posted job, and why none is posted.
///
/// # Errors
///
/// The handle's fault.
pub fn mining_status(mining: &dyn MiningFacts) -> Result<MiningStatusResponse, RpcError> {
    let state = mining.status()?;
    let (difficulty, wide_difficulty, difficulty_top64) =
        split_128(state.posted.map_or(0, |posted| posted.difficulty));
    Ok(MiningStatusResponse {
        status: RpcStatus::ok(),
        active: state.miner.is_some(),
        speed: state.miner.map_or(0, |miner| miner.hashes_per_second),
        threads_count: state.miner.map_or(0, |miner| miner.threads),
        address: state.address.unwrap_or_default(),
        pow_algorithm: POW_ALGORITHM.to_owned(),
        block_target: u32::try_from(shekyl_difficulty::T_SECONDS).unwrap_or(u32::MAX),
        block_reward: state.posted.map_or(0, |posted| posted.reward),
        difficulty,
        wide_difficulty,
        difficulty_top64,
        height: state.posted.map_or(0, |posted| posted.height.to_raw()),
        pool_retired: state.pool_retired,
        no_template: state.absent,
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

/// `submit_block { body }`: a block, through the node's local-arrival
/// entry (b4). Its listed bodies come from the pool. It succeeds when the
/// block connects, or when it is the new tip after a switch.
///
/// # Errors
///
/// `BadParams` for a body that is not a block; otherwise the outcome's
/// class and diagnostic: `MissingBodies` names the indices.
pub async fn submit_block(
    door: &dyn DoorFacts,
    request: SubmitBlockRequest,
) -> Result<SubmitBlockResponse, RpcError> {
    let malformed = |what: String| {
        RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::BLOCK_MALFORMED, what),
        )
    };
    let bytes = hex::decode(&request.body)
        .map_err(|e| malformed(format!("the block is not hexadecimal: {e}")))?;
    let block = shekyl_wire::Block::from_bytes(&bytes)
        .map_err(|e| malformed(format!("the bytes are not a block: {e}")))?;
    let hash = block.hash();
    match door.offer_local(bytes).await? {
        LocalOutcome::Connected { .. } | LocalOutcome::Switched { .. } => Ok(SubmitBlockResponse {
            status: RpcStatus::ok(),
            block_id: hash_hex(hash),
        }),
        other => Err(not_joined(other)),
    }
}

/// Stops, on drop, a miner `generateblocks` started: a caller that goes
/// away mid-wait leaves no miner running. The stop joins the workers, so
/// on a runtime it runs on a blocking thread.
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
                tracing::error!("generateblocks: the miner it started did not stop: {fault:?}");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(stop)),
            Err(_) => stop(),
        }
    }
}

/// `generateblocks { count }`, an armed lever (b6): start the built-in
/// miner if it is stopped, wait until the tip is `count` blocks higher,
/// and stop the miner if this call started it — on return, and when the
/// call is dropped mid-wait. The blocks are the node's own template's,
/// paying its `mine-address` (N2).
///
/// It is refused at once while the job is withdrawn for a reason the next
/// tip does not clear (not synced, no address, the pool retired), and the
/// wait ends when it is withdrawn for such a reason: no miner can move the
/// tip without a job. A reason that clears itself — the node starting, or
/// between two tips — is waited out, before the wait as during it
/// ([`MiningFacts::withdrawn`]).
///
/// # Errors
///
/// `BadParams` for a count of zero; `NotReady` with the node's reason when
/// the job is withdrawn for a reason the next tip does not clear, before or
/// during the wait; the miner's refusal; `NotReady` when the node stops
/// first.
pub async fn generateblocks(
    mining: &MiningHandle,
    door: &dyn DoorFacts,
    chain: &dyn ChainFacts,
    _armed: Armed,
    request: GenerateBlocksRequest,
) -> Result<GenerateBlocksResponse, RpcError> {
    if request.count == 0 {
        return Err(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::COUNT_ZERO, "count must be at least one"),
        ));
    }
    // One poll of the withdrawal: resolved now is a reason the next tip
    // does not clear, refused before a miner starts; pending is a job
    // posted, or a reason that clears itself, waited out below.
    tokio::select! {
        biased;
        lost = mining.withdrawn() => {
            return Err(match lost {
                Ok(why) => RpcError::new(ErrorClass::NotReady, why),
                Err(fault) => RpcError::from(fault),
            });
        }
        () = std::future::ready(()) => {}
    }
    let start = chain.chain_tip()?.chain_height;
    let wanted = BlockCount::from_raw(request.count);
    let Some(target) = start.checked_add(wanted).and_then(ChainCount::tip) else {
        return Err(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::COUNT_OVERFLOW, "count does not fit on this chain")
                .param("count", request.count.to_string())
                .param("chain_height", start.to_raw().to_string()),
        ));
    };
    let started = match on_a_blocking_thread(mining, |mining| mining.start(None)).await? {
        Ok(()) => StartedMiner(Some(std::sync::Arc::clone(mining))),
        Err(running) if running.code == codes::RUNNING => StartedMiner(None),
        Err(refused) => return Err(RpcError::new(ErrorClass::RefusedByMethod, refused)),
    };
    let reached = tokio::select! {
        reached = door.tip_at_least(target) => reached.map_err(RpcError::from),
        lost = mining.withdrawn() => Err(match lost {
            Ok(why) => RpcError::new(ErrorClass::NotReady, why),
            Err(fault) => RpcError::from(fault),
        }),
    };
    started.stop().await?;
    reached?;
    let end = chain.chain_tip()?.chain_height;
    let mut blocks = Vec::new();
    for height in start.next_height().ordinals_until(end.next_height()) {
        if let Some(hash) = chain.block_hash_at(height)?.hash {
            blocks.push(hash_hex(hash));
        }
    }
    Ok(GenerateBlocksResponse {
        status: RpcStatus::ok(),
        height: end.to_raw(),
        blocks,
    })
}

/// `/pop_blocks { nblocks }`, an armed lever (DX-Q3, Q7): pop that many
/// blocks from the tip; their transactions return to the pool.
///
/// # Errors
///
/// `RefusedByMethod` when the pop would remove genesis or a block the undo
/// journal retired; nothing was popped, and the node is up.
pub async fn pop_blocks(
    door: &dyn DoorFacts,
    _armed: Armed,
    request: PopBlocksRequest,
) -> Result<PopBlocksResponse, RpcError> {
    match door.pop(request.nblocks).await? {
        PopOutcome::Popped { tip } => {
            let height = ChainCount::with_tip(tip).ok_or_else(|| {
                RpcError::new(
                    ErrorClass::Internal,
                    Diagnostic::new(codes::INTERNAL, "the tip has no chain count"),
                )
            })?;
            Ok(PopBlocksResponse {
                status: RpcStatus::ok(),
                height: height.to_raw(),
            })
        }
        PopOutcome::Refused { tip, floor } => Err(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::POP_BELOW_FLOOR,
                format!(
                    "popping {} blocks from tip {} would remove a block below the lowest poppable height, {}",
                    request.nblocks,
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

    /// An absent node is not ready, never an empty or zero answer
    /// (RK-D23), on every mining method.
    #[tokio::test]
    async fn an_absent_node_is_not_ready_on_every_mining_method() {
        let handles = Handles::absent();
        let class = |error: RpcError| error.class;
        assert_eq!(
            get_block_template(&*handles.mining).map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            get_miner_data(&*handles.mining).map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            mining_status(&*handles.mining).map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            stop_mining(&handles.mining).await.map_err(class),
            Err(ErrorClass::NotReady)
        );
        assert_eq!(
            start_mining(&handles.mining, StartMiningRequest::default())
                .await
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

    /// An armed lever is refused outside the grant while the switch is off,
    /// whoever asks; a row that is not armed always passes.
    #[test]
    fn an_armed_lever_is_outside_the_grant_until_the_switch_is_on() {
        let generate = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
        let refused = admit_armed(generate, false).expect_err("unarmed");
        assert_eq!(refused.class, ErrorClass::OutsideTheGrant);
        assert_eq!(refused.diagnostic.code, codes::UNARMED);
        assert!(admit_armed(generate, true).is_ok());
        let pop = shekyl_rpc_types::methods::rest_path("/pop_blocks").expect("a row");
        assert!(admit_armed(pop, false).is_err());
        let template = shekyl_rpc_types::methods::json_rpc("get_block_template").expect("a row");
        assert!(admit_armed(template, false).is_ok());
    }

    /// A node between states: its job is withdrawn as starting, a reason
    /// the next tip clears, so `withdrawn` never resolves; the tip the
    /// call waits for is already reached.
    struct Starting {
        stops: std::sync::atomic::AtomicUsize,
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
        fn stop(&self) -> Result<bool, FactsFault> {
            self.stops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        fn status(&self) -> Result<crate::mining_facts::MiningState, FactsFault> {
            unreachable!("generateblocks reads no status")
        }
        fn withdrawn(&self) -> crate::mining_facts::Pending<'_, Diagnostic> {
            Box::pin(std::future::pending())
        }
    }

    struct Reached;

    impl DoorFacts for Reached {
        fn room(&self) -> Result<usize, FactsFault> {
            unreachable!("generateblocks takes no room")
        }
        fn offer_local(&self, _block: Vec<u8>) -> crate::mining_facts::Pending<'_, LocalOutcome> {
            unreachable!("generateblocks offers nothing")
        }
        fn pop(&self, _count: u64) -> crate::mining_facts::Pending<'_, PopOutcome> {
            unreachable!("generateblocks pops nothing")
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
            })
        }
        fn identity(&self) -> Result<crate::chain_facts::DaemonIdentity, FactsFault> {
            unreachable!("generateblocks reads no identity")
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
            unreachable!("generateblocks reads no header")
        }
        fn fee_estimate(&self) -> Result<crate::chain_facts::FeeEstimate, FactsFault> {
            unreachable!("generateblocks reads no fee")
        }
        fn block_at(
            &self,
            _at: crate::chain_facts::BlockLookup,
            _fill_pow_hash: bool,
        ) -> Result<crate::chain_facts::BlockAt, FactsFault> {
            unreachable!("generateblocks reads no block")
        }
    }

    /// `generateblocks` on a node whose job is withdrawn for a reason that
    /// clears itself (starting, or between two tips) waits it out instead
    /// of refusing, and stops the miner it started (the landing review of
    /// #1165, N4). Red edit: refuse whenever no job is posted.
    #[tokio::test]
    async fn generateblocks_waits_out_a_reason_that_clears_itself() {
        let mining: MiningHandle = std::sync::Arc::new(Starting {
            stops: std::sync::atomic::AtomicUsize::new(0),
        });
        let row = shekyl_rpc_types::methods::json_rpc("generateblocks").expect("a row");
        let generated = generateblocks(
            &mining,
            &Reached,
            &Genesis,
            admit_armed(row, true).expect("armed"),
            GenerateBlocksRequest { count: 1 },
        )
        .await
        .expect("waited out, not refused");
        assert_eq!(generated.height, 1);
    }
}
