// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`CurveTreeActor`]: the CT-5 `kameo` actor that owns the wallet's
//! [`CurveTreeClient`], and [`CurveTreeHandle`]: the `Clone` handle the
//! orchestrator holds in place of an inline client field.
//!
//! Per [`docs/design/CT5_ENGINE_WIRING.md`] §3.1, the curve-tree client is
//! placed behind a `kameo` actor for the **redb single-writer** reason (the
//! [`LeafStore`](shekyl_curve_tree::LeafStore) is a single-writer redb
//! database; the actor's single-threaded message loop serializes writes
//! without an explicit lock), not as a "standing principle." The reversion
//! target if that argument dissolves is an `RwLock<CurveTreeClient>` (§3.1 /
//! E0). `Engine` holds a [`CurveTreeHandle`] exactly as it holds a
//! [`KeyEngineHandle`](super::key_actor::KeyEngineHandle) in place of an
//! `AllKeysBlob` field.
//!
//! # No secrets (contrast [`KeyActor`](super::key_actor::KeyActor))
//!
//! The curve tree is reconstructed from **public on-chain material only** — no
//! wallet secret enters [`shekyl_curve_tree`] (`35-secure-memory.mdc`,
//! `36-secret-locality.mdc`; see the crate-level docs). So, unlike
//! [`KeyActor`], this actor has **no `on_stop` zeroization** and its messages
//! and replies carry no secret bytes. The mirror is structural (actor +
//! `Clone` handle + `ask`-dispatched messages), not cryptographic.
//!
//! # Two-clause lock-ordering invariant (CT-5a structural rule — §3.1 / E2)
//!
//! Holding the engine's `RwLock` write guard across an `.await` that
//! round-trips to another actor is the classic async-deadlock shape if the
//! awaited actor ever (directly or transitively) wants that same engine lock.
//! The durable defense is a *structural constraint*, pinned with the same
//! review status as the no-secrets discipline:
//!
//! 1. The [`CurveTreeActor`] struct owns **only the store handle** (the
//!    [`CurveTreeClient`]) and holds **no `Engine` / `EngineHandle` /
//!    engine-lock reference** of any kind. A field addition that reaches back
//!    for engine state fails review **on this rule** — not on someone
//!    re-deriving the deadlock analysis. This is mechanically guarded by
//!    [`tests::actor_constructed_from_only_the_client`]: the actor's
//!    [`Actor::Args`] is pinned to `CurveTreeClient`, and `on_start` receives
//!    only `Args` plus a [`WeakActorRef`] (no engine state), so any field that
//!    needed engine state would have to enter through `Args` and break that
//!    bound.
//! 2. Recovery from a poisoned client runs **inside the actor**, as the
//!    [`Recover`] message: it rebuilds the client from the store the actor
//!    already owns and touches nothing else, so no handler ever reaches back
//!    for engine state. The engine sends it after the failed `ask` returns,
//!    never from inside a handler awaited under the guard.
//!
//! Corollary: *the curve-tree actor never acquires the engine lock; the engine
//! may hold its lock across a curve-tree `ask`.*
//!
//! # One owner, and its stop is awaited
//!
//! The actor owns the client, and with it the redb file, outright
//! (`CURVE_TREE_CLIENT.md` §11, ruled 2026-11-02; the wallet's actor rule,
//! `V3_WALLET_DECISION_LOG.md` 2026-04-27). Nothing outside it holds the
//! store. [`CurveTreeHandle::shutdown`] stops the actor and awaits
//! `wait_for_shutdown_result`, and [`Actor::on_stop`] drops the client. In
//! `kameo` 0.20.0 that result is set only after `on_stop` returns
//! (`src/actor/spawn.rs`), so when the await returns, the file is closed and
//! a reopen succeeds at once. `wait_for_shutdown` is not enough: it waits for
//! the mailbox to close, which happens *before* `on_stop` runs.
//!
//! # Fail-stop, not supervised
//!
//! A panic in a handler runs [`Actor::on_panic`], which returns
//! [`ControlFlow::Break`] so the actor stops rather than restarts. After a
//! stop, every [`CurveTreeHandle`] call collapses the kameo transport failure
//! into [`CurveTreeHandleError::Unavailable`], terminal for the session, as
//! [`KeyActor`]'s is. The workspace builds with `panic = "abort"`, so in a
//! release a handler panic ends the process. The recoverable fault is a
//! poisoned client, which [`Recover`] heals in place.
//!
//! [`docs/design/CT5_ENGINE_WIRING.md`]: ../../../../../docs/design/CT5_ENGINE_WIRING.md

use std::ops::ControlFlow;
use std::sync::Arc;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_curve_tree::{
    AssembleInput, AssembledPath, BlockHeight, BlockLeaves, ClientError, CurveTreeClient,
    PostureDeclaration, ReferenceBlock, SegmentPin, TxLeafInputs,
};

use crate::scan::OwnedTxLeaves;
use shekyl_types::CurveTreeRoot;

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// The CT-5 `kameo` actor that owns the wallet's [`CurveTreeClient`] and serves
/// the actor-dispatched ingest / rollback operations ([`IngestBlock`],
/// [`RollbackToFork`]).
///
/// The actor's single-threaded message loop serializes access to `client`,
/// which is the redb single-writer property the actor exists to enforce
/// (§3.1).
pub(crate) struct CurveTreeActor {
    /// The wallet's FCMP++ curve-tree client (redb-backed, public material).
    ///
    /// **Lock-ordering clause 1 (§3.1 / E2): this is the actor's ONLY field.**
    /// It holds no `Engine` / `EngineHandle` / engine-lock reference. See the
    /// module docs; the invariant is mechanically guarded by
    /// [`tests::actor_constructed_from_only_the_client`].
    ///
    /// `Some` for the actor's whole life; [`Actor::on_stop`] takes it, so the
    /// store closes before the stop can be observed (module docs).
    client: Option<CurveTreeClient>,
}

impl CurveTreeActor {
    /// The client, for a handler. kameo runs no handler after `on_stop`, the
    /// only place it is taken, so a handler always finds it.
    fn client(&mut self) -> &mut CurveTreeClient {
        self.client
            .as_mut()
            .expect("kameo runs no handler after on_stop, which alone takes the client")
    }
}

impl Actor for CurveTreeActor {
    type Args = CurveTreeClient;
    type Error = Infallible;

    /// Build the actor from the moved-in [`CurveTreeClient`]. The client is the
    /// **only** construction input (clause 1).
    async fn on_start(
        client: CurveTreeClient,
        _actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            client: Some(client),
        })
    }

    /// Fail-stop on panic. This is the kameo default, overridden explicitly so
    /// the no-restart posture is locked at the type layer rather than inherited
    /// from a framework default that could change under a dependency bump. The
    /// actor does not restart; see the module docs.
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Drop the client here, not with the actor value: kameo drops the value
    /// after the shutdown result is set, and sets it after `on_stop`
    /// returns, so this is what makes [`CurveTreeHandle::shutdown`]'s await
    /// mean the redb file is closed. No zeroization: the client carries no secret bytes
    /// (contrast `KeyActor::on_stop`, which wipes `AllKeysBlob`).
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        drop(self.client.take());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Actor message for [`CurveTreeClient::ingest_block`]: append one block's
/// leaves at the next consecutive height. Carries [`BlockHeight`] across the
/// actor boundary (not an unwrapped `u64`) — the CT-3a P5 cross-seam typing.
pub(crate) struct IngestBlock {
    /// The block's height (must equal the client's ingested-tip + 1).
    pub height: BlockHeight,
    /// The block's transactions in block order (coinbase first). Carried
    /// behind an `Arc` so the cursor-driven ingest driver can hand the actor
    /// a height's leaves while *retaining* its own reference: a failed `ask`
    /// on a poisoned client consumes this message, but the driver's `Arc`
    /// survives for the recover-and-retry resend ([`Recover`]) — no deep
    /// clone, no lost leaf set.
    pub txs: Arc<Vec<OwnedTxLeaves>>,
}

/// Actor message for [`CurveTreeClient::rollback_to_fork`]: drop all leaves
/// after `fork_height` on a reorg. Carries [`BlockHeight`] across the boundary.
pub(crate) struct RollbackToFork {
    /// The last height that survives the reorg; leaves above it are dropped.
    pub fork_height: BlockHeight,
}

/// Actor message reading [`CurveTreeClient::ingested_tip_height`]: the tree's
/// authoritative resume cursor (`None` when fresh). Carries no payload.
///
/// **D2 — cursor-driven resume (`CT5_ENGINE_WIRING.md` §3.2.1.1).** The forward
/// / backfill ingest driver reads its resume point from this message on every
/// iteration and holds **no** driver-local fetch-frontier field, so a reorg that
/// rewinds the cursor ([`RollbackToFork`] rebuilds it from the store) is
/// observed on the next read. Counter-drift is unrepresentable, not merely
/// forbidden by discipline.
///
/// The reply is `Result<Option<BlockHeight>, ClientError>` for collapse
/// uniformity with [`IngestBlock`] / [`RollbackToFork`] (so the one
/// [`collapse_send_error`] maps every transport failure to
/// [`CurveTreeHandleError::Unavailable`]); the handler is infallible and always
/// replies `Ok`, so the [`CurveTreeHandleError::Client`] arm is unreachable for
/// this message.
pub(crate) struct IngestedTipHeight;

/// Actor message rebuilding a poisoned client in place, over the store the
/// actor owns ([`CurveTreeClient::rebuild`]). The recovery
/// [`CurveTreeIngestFault::ClientPoisoned`](super::error::CurveTreeIngestFault::ClientPoisoned)
/// names; it never reopens the file and never mints a second writer. The
/// rebuilt client holds no output registrations, so the engine's retry
/// re-offers them, as after a fresh open.
pub(crate) struct Recover;

/// Actor message for the persona serving host's pin (SH-2): pin every shard
/// in `shard_ids`, release `release_ids`, and report the pin set after.
///
/// **The store the pins landed in is this actor's.** `shekyl-p-host`'s
/// `ServeSetPinner` contract is that the report names the store the pins
/// were written to, and every later reading names it too. This actor owns
/// one store for its life ([`CurveTreeHandle::store_identity`]); an
/// in-place rebuild resumes over that store and keeps the actor, so the
/// pins and every later [`ReadStoreFacts`] through the same handle are
/// about the same store. No handle on the store leaves the actor.
///
/// The pin is a **store write**, which is why it lives here at all: the
/// actor's message loop is what serializes writes on the single-writer redb
/// store, so a serving host reaching the store directly would be a second
/// writer beside the one this actor exists to be.
pub(crate) struct PinServeSet {
    /// Shard ids from the connected bond record, in the record's order.
    pub shard_ids: Vec<u64>,
    /// Shard ids whose pins the caller has determined are releasable — absent
    /// from the record across two consecutive settlement-epoch opens, so the
    /// last epoch the pair could have been drawn in closed a full epoch ago.
    /// The gate is the caller's (`EngineServeSetPinner::releasable`, where the
    /// reasoning lives); this message only carries its result.
    ///
    /// Carried on the same message as the pin rather than sent as its own so
    /// the two land in one actor turn, in the one order that is safe: pin the
    /// current set, *then* release. Empty on most refreshes.
    pub release_ids: Vec<u64>,
}

/// What one serve-set reconcile reports back.
///
/// `pinned_now` is the input the *next* reconcile needs: a refresh can only
/// tell which pins are stale by comparing the store's pin set against the
/// record it just read, and only the actor can see the former. Returning it
/// here keeps the whole reconcile at one round trip per refresh — the release
/// then lags by one refresh, which against an epoch-scale gate is not a lag
/// that means anything.
pub(crate) struct PinServeSetReply {
    /// Per-member pin outcome, paired with its shard id, in caller order.
    pub outcomes: Vec<(u64, SegmentPin)>,
    /// Every shard id pinned in the store *after* this reconcile.
    pub pinned_now: Vec<u64>,
    /// How many pins this reconcile actually removed.
    pub released: usize,
}

/// Actor message for the **CompleteTree prefix** serve-set: declare the
/// prune-disabled posture, then read the freeze cursor — one message, in
/// that order (`COMPLETETREE_ACTIVATION.md` D-1/D-5, RR-2).
///
/// The corpus sibling of [`PinServeSet`], and deliberately a **separate
/// message rather than a mode flag on it**: the two arms take and return
/// different things (a shard list and per-member outcomes versus no input
/// and a cursor), and a flag would rebuild inside one message the very
/// conflation the two-armed `ReportedSet` was split to remove.
///
/// # Why the order is the message, not the caller's discipline
///
/// `ServeSetPinner`'s prefix contract is **declare-before-report**: the
/// `PostureDeclaration` a report carries is the loss detector for the gap a
/// re-declaring refresh repairs, so it has to be the answer the store gave
/// *for this report*, and the cursor has to be the one that declaration
/// vouches for. Both run here, in this order, so no caller can get the
/// sequence wrong and no caller can pair a declaration with a cursor read
/// from a different moment.
///
/// **The handler invocation is the atomicity unit** — the same guarantee
/// [`AssembleTx`] documents for read-path snapshots and [`PinServeSet`]
/// relies on for pin-then-release. The cursor moves only through this
/// actor's own ingest / truncate / rollback messages, kameo processes one
/// message at a time, and the store is opened exclusively — so nothing can
/// advance the freeze prefix between the declaration and the read. Two
/// store calls rather than one redb transaction, therefore, with the
/// property the transaction would have bought delivered by the serialization
/// that already governs every other write on this actor.
pub(crate) struct PinCompleteTreePrefix;

/// What [`PinCompleteTreePrefix`] reports: the declaration answer and the
/// prefix length it vouches for.
pub(crate) struct PinCompleteTreePrefixReply {
    /// What the store found when this call declared the posture —
    /// `NewlyDeclared` from an already-serving wallet is the evidence a
    /// one-way flag was lost, which the witness answers with the corpus
    /// integrity scan.
    pub declaration: PostureDeclaration,
    /// The burial-gated freeze cursor: the obligation is `[0, frozen_count)`.
    pub frozen_count: u64,
}

/// Actor message reading what the serving host's witness checks, in one
/// handler invocation so the readings describe one moment of the store:
/// the ingest tip, the posture flag, the freeze cursor, and which members
/// of `claimed` have lost their pin rows.
///
/// These are the reads a `ServingReader` used to make from beside the
/// actor (*records-was, until 2026-11-02*); asked by message, nothing
/// outside the actor holds the store open (`CURVE_TREE_CLIENT.md` §11).
pub(crate) struct ReadStoreFacts {
    /// The members whose pin rows to check.
    pub claimed: Vec<u64>,
}

/// What [`ReadStoreFacts`] reads.
pub(crate) struct StoreFactsReply {
    /// The store's ingest tip.
    pub sync_tip_height: BlockHeight,
    /// Whether the prune-disabled posture is declared.
    pub prune_disabled: bool,
    /// The burial-gated freeze cursor.
    pub next_freeze_seg: u64,
    /// The members of `claimed` whose pin row is gone.
    pub members_missing_pins: Vec<u64>,
}

/// Actor message for the corpus integrity scan: the frozen segments the
/// store has already pruned. O(D); the witness asks for it only where its
/// policy runs the scan.
pub(crate) struct ScanPrunedFrozenSegments;

/// Actor message for the §3.3 ingest-time integrity verify (CT-5b): reconstruct
/// the curve-tree root at `height` and require it to byte-equal the consensus
/// header-committed `expected_root`. Replies [`ClientError::RootMismatch`] on
/// divergence — the lying-daemon (O5) defense: the wallet refuses to advance
/// past a tree state it ingested but cannot reproduce against the header the
/// producer claimed.
///
/// This is the compare sibling of the [`RootAndDepthAt`] read-back — both are
/// production root operations (`RootAndDepthAt` returns the reconstructed root
/// and depth, `VerifyRoot` compares the root against an expected value). It is
/// keyed by `(height, expected_root)` rather than a full
/// [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock) because ingest has no
/// `block_hash` to anchor — the header root is the only field
/// [`CurveTreeClient::verify_root`] consults, so this mirrors its compare
/// without fabricating the unused field.
pub(crate) struct VerifyRoot {
    /// The height whose reconstructed root to check (must be `<=` ingested tip).
    pub height: BlockHeight,
    /// The consensus header-committed root the reconstruction must match.
    pub expected_root: CurveTreeRoot,
}

/// Actor message reading [`CurveTreeClient::root_and_depth_at`]: the
/// reconstructed root **and** the tree depth at `height`, both pinned to the
/// same drained leaf count (CT-5c Q1).
///
/// The send path needs both before assembling: the depth sizes the FCMP++
/// proof weight for fee estimation (which runs before path assembly), and the
/// root binds the [`ReferenceBlock`]. Read together in one handler invocation
/// so they describe the same tree state. This is also the read-back the CT-5a
/// commit-6 oracle KAT (in `refresh.rs`) uses — taking the root, ignoring the
/// depth — to assert the ingest path reproduces the consensus header root.
pub(crate) struct RootAndDepthAt {
    /// The reference height whose reconstructed root and depth to read.
    pub height: BlockHeight,
}

/// Actor message assembling every membership path for one transaction in a
/// single handler invocation (CT-5c T3 / Q2).
///
/// The handler makes one [`CurveTreeClient::assemble_paths`] call over `inputs`
/// against the one shared `reference`, which reconstructs the drained leaves
/// and their layers **once for the batch** instead of once per input
/// (`CT-6` increment 3, closeout row (a)). Because the actor processes messages serially,
/// no [`IngestBlock`] / [`RollbackToFork`] interleaves mid-assembly — the
/// read-path snapshot atomicity (E1) is the handler invocation itself, not a
/// discipline the caller must uphold. One `reference` for the whole batch makes
/// the C1 single-snapshot guarantee (every input shares one tree context) the
/// only representable shape. Bounded by `shekyl_tx_builder::MAX_INPUTS` — which
/// is defined as `= shekyl_fcmp::MAX_INPUTS`, so the engine bound and the FCMP++
/// proof-system limit are one constant, not two that could drift — at the
/// handler boundary so an over-length request cannot spin the actor.
pub(crate) struct AssembleTx {
    /// The single reference block every input's path anchors to (C1).
    pub reference: ReferenceBlock,
    /// The owned outputs to assemble paths for, in transaction input order; the
    /// reply preserves that order.
    pub inputs: Vec<AssembleInput>,
}

impl Message<IngestBlock> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        msg: IngestBlock,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Re-borrow the owned payload into the borrowing `BlockLeaves` the
        // client API consumes. The borrows live only for this call.
        let txs: Vec<TxLeafInputs<'_>> = msg
            .txs
            .iter()
            .map(|tx| TxLeafInputs {
                is_miner: tx.is_miner,
                tx_hash: Some(tx.tx_hash),
                leaf_entry_blob: tx.leaf_entry_blob.as_deref(),
                outputs: tx.outputs.as_slice(),
            })
            .collect();
        self.client().ingest_block(BlockLeaves {
            height: msg.height,
            txs: &txs,
        })
    }
}

impl Message<PinServeSet> for CurveTreeActor {
    type Reply = Result<PinServeSetReply, ClientError>;

    async fn handle(
        &mut self,
        msg: PinServeSet,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // **Pin before release, always.** Both run on the actor's own object,
        // so nothing else interleaves — but the order still matters, because a
        // release that ran first would leave a window in which a shard this
        // refresh still owes is unpinned and prunable. Pinning first makes the
        // only reachable transient an *extra* pin, which fails toward
        // retention. Same asymmetry §9.7 item 5 rules for the verbs themselves.
        let outcomes = self.client().pin_serve_set(&msg.shard_ids)?;
        let released = if msg.release_ids.is_empty() {
            0
        } else {
            self.client().release_pins(&msg.release_ids)?
        };
        Ok(PinServeSetReply {
            outcomes,
            pinned_now: self.client().pinned_shard_ids()?,
            released,
        })
    }
}

impl Message<PinCompleteTreePrefix> for CurveTreeActor {
    type Reply = Result<PinCompleteTreePrefixReply, ClientError>;

    async fn handle(
        &mut self,
        _msg: PinCompleteTreePrefix,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // **Declare before read, always** — see the message doc. The
        // declaration is idempotent and one-way, so re-declaring costs an
        // MVCC read in the steady state and the durable write happens once.
        let declaration = self.client().set_prune_disabled()?;
        let frozen_count = self.client().next_freeze_seg()?;
        Ok(PinCompleteTreePrefixReply {
            declaration,
            frozen_count,
        })
    }
}

impl Message<ReadStoreFacts> for CurveTreeActor {
    type Reply = Result<StoreFactsReply, ClientError>;

    async fn handle(
        &mut self,
        msg: ReadStoreFacts,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let client = self.client();
        Ok(StoreFactsReply {
            sync_tip_height: client.sync_tip_height()?,
            prune_disabled: client.prune_disabled()?,
            next_freeze_seg: client.next_freeze_seg()?,
            members_missing_pins: client.members_missing_pins(&msg.claimed)?,
        })
    }
}

impl Message<ScanPrunedFrozenSegments> for CurveTreeActor {
    type Reply = Result<Vec<u64>, ClientError>;

    async fn handle(
        &mut self,
        _msg: ScanPrunedFrozenSegments,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().pruned_frozen_segments()
    }
}

impl Message<RollbackToFork> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        msg: RollbackToFork,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().rollback_to_fork(msg.fork_height)
    }
}

impl Message<IngestedTipHeight> for CurveTreeActor {
    type Reply = Result<Option<BlockHeight>, ClientError>;

    async fn handle(
        &mut self,
        _msg: IngestedTipHeight,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Infallible cursor read; wrapped in `Ok` only for collapse uniformity.
        Ok(self.client().ingested_tip_height())
    }
}

/// Test-only message behind [`CurveTreeHandle::poison_for_test`].
#[cfg(test)]
pub(crate) struct PoisonForTest;

#[cfg(test)]
impl Message<PoisonForTest> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        _msg: PoisonForTest,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().test_tamper_poison();
        Ok(())
    }
}

impl Message<Recover> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        _msg: Recover,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().rebuild()
    }
}

impl Message<VerifyRoot> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        msg: VerifyRoot,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Mirror `CurveTreeClient::verify_root`'s compare, keyed by the header
        // root the ingest path carries (no `block_hash` at ingest). A store
        // error from `root_at` (e.g. `Poisoned`) propagates as-is; only a
        // genuine divergence becomes `RootMismatch`.
        let got = self.client().root_at(msg.height)?;
        if got == msg.expected_root {
            Ok(())
        } else {
            Err(ClientError::RootMismatch {
                height: msg.height,
                expected: msg.expected_root,
                got,
            })
        }
    }
}

impl Message<RootAndDepthAt> for CurveTreeActor {
    type Reply = Result<([u8; 32], u8), ClientError>;

    async fn handle(
        &mut self,
        msg: RootAndDepthAt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client()
            .root_and_depth_at(msg.height)
            .map(|(root, depth)| (root.to_bytes(), depth))
    }
}

impl Message<AssembleTx> for CurveTreeActor {
    type Reply = Result<Vec<AssembledPath>, ClientError>;

    async fn handle(
        &mut self,
        msg: AssembleTx,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Handler-boundary bound (Q2): refuse an over-length batch before the
        // loop so a buggy or hostile caller cannot spin the single-writer actor.
        // The engine's selection is independently bounded, so this never fires
        // in production — it makes the bad state unrepresentable at the actor
        // boundary, not merely upstream of it. `shekyl_tx_builder::MAX_INPUTS`
        // is `= shekyl_fcmp::MAX_INPUTS` (a re-export), so this is the canonical
        // FCMP++ proof limit — engine-core depends on tx-builder, not fcmp.
        if msg.inputs.len() > shekyl_tx_builder::MAX_INPUTS {
            return Err(ClientError::TooManyInputs {
                got: msg.inputs.len(),
                max: shekyl_tx_builder::MAX_INPUTS,
            });
        }
        // The capture path is total, and this is where that is made so: the
        // batch's inputs are registered in the SAME handler invocation that
        // assembles them, so no ingest or rollback interleaves (E1) and no
        // input reaches `assemble_paths` unregistered — whether the wallet's
        // refresh registered it earlier or not, and whichever orchestrator is
        // asking (spend, claim, bond, release). A re-offer of a held pair is
        // `AlreadyHeld` and costs a map lookup; an input owed captures is
        // reconciled here, once. A stale pair — the client holds a different
        // output at that gindex — is left unregistered and the assembly then
        // refuses it by name, which is the caller's stale view surfacing as
        // `OutputNotRegistered` rather than as a wrong-leaf proof.
        let pairs: Vec<(shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey)> = msg
            .inputs
            .iter()
            .map(|input| (input.gindex, input.output_key))
            .collect();
        let sync = self.client().sync_owned(&pairs)?;
        if !sync.stale.is_empty() {
            tracing::warn!(
                stale = sync.stale.len(),
                "assemble: inputs whose key disagrees with the tree; the caller's \
                 view is behind the chain and the assembly will refuse them"
            );
        }
        // One handler invocation = one snapshot: every path is assembled
        // against the same `reference` with no ingest/rollback interleave (E1).
        // `assemble_paths` reads each input's captures and the snapshot at
        // the reference (`CT-6` increment 5), so the shared snapshot is a
        // property of the values as well as of the `reference`.
        self.client().assemble_paths(&msg.inputs, &msg.reference)
    }
}

/// Register a batch of owned outputs, reconciling once if any is owed.
///
/// The wallet's refresh sends everything it holds on every pass — a resume
/// is a mass late registration, and the registry does not persist — and the
/// scan's newly inserted transfers after each merge. See
/// [`CurveTreeClient::sync_owned`] for the per-pair verdicts and why a stale
/// pair is reported rather than fatal.
pub(crate) struct SyncOwned {
    /// `(gindex, O)` per output; the pair, because a gindex is a name a
    /// reorg re-derives and `O` is the identity that survives it.
    pub(crate) outputs: Vec<(shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey)>,
}

impl Message<SyncOwned> for CurveTreeActor {
    type Reply = Result<shekyl_curve_tree::OwnershipSync, ClientError>;

    async fn handle(
        &mut self,
        msg: SyncOwned,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().sync_owned(&msg.outputs)
    }
}

/// Replace the outputs the wallet expects and register the pairs it already
/// holds, in that order, inside one handler invocation.
///
/// The refresh offers both between its rollback and its first fold. Two asks
/// would let an ingest run after the expectations were set and before the
/// pairs were registered. One invocation is the actor's atomicity, the same
/// one [`AssembleTx`] uses for a spend's inputs. Expectations are set even
/// when `outputs` is empty: clearing the set is itself the offer.
pub(crate) struct OfferOwned {
    /// `(tx_hash, vout, O)` per output the wallet built and has not yet seen
    /// mined. Replaces the previous set
    /// ([`CurveTreeClient::set_expected_outputs`]).
    pub(crate) expected: Vec<shekyl_curve_tree::ExpectedOutput>,
    /// `(gindex, O)` per output already held. Registered after the
    /// expectations ([`CurveTreeClient::sync_owned`]).
    pub(crate) outputs: Vec<(shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey)>,
}

impl Message<OfferOwned> for CurveTreeActor {
    type Reply = Result<shekyl_curve_tree::OwnershipSync, ClientError>;

    async fn handle(
        &mut self,
        msg: OfferOwned,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client().set_expected_outputs(&msg.expected)?;
        self.client().sync_owned(&msg.outputs)
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Error from a [`CurveTreeHandle`] call.
///
/// Mirrors the [`KeyEngineHandle`](super::key_actor::KeyEngineHandle) send-error
/// collapse: a handler error carries the real [`ClientError`] the client
/// returned (e.g. [`ClientError::NonConsecutiveBlockHeight`],
/// [`ClientError::Poisoned`]); every other `ask` transport failure maps to
/// [`Unavailable`](CurveTreeHandleError::Unavailable), which is terminal for
/// the session.
#[derive(Debug)]
pub(crate) enum CurveTreeHandleError {
    /// The client returned an error inside the handler.
    Client(ClientError),
    /// The `ask` could not be delivered to or answered by a live handler — the
    /// actor is fail-stopped or stopped (`ActorNotRunning` / `ActorStopped`),
    /// or the request timed out (`Timeout`). `MailboxFull` also collapses here
    /// for match exhaustiveness but is unreachable on the awaiting `ask` path:
    /// the `ask` future applies backpressure by blocking the sender until
    /// capacity frees rather than returning `MailboxFull` (mirrors the
    /// [`key_actor`](super::key_actor) §4.4 T4 note). Terminal: a stopped
    /// actor is not restarted (module docs).
    Unavailable,
}

/// Collapse a kameo `ask` [`SendError`] into a [`CurveTreeHandleError`].
fn collapse_send_error<M>(err: SendError<M, ClientError>) -> CurveTreeHandleError {
    match err {
        SendError::HandlerError(e) => CurveTreeHandleError::Client(e),
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => CurveTreeHandleError::Unavailable,
    }
}

/// `Clone` handle the orchestrator holds in place of an inline `CurveTreeClient`
/// field: the actor's [`ActorRef`], and nothing else. It is `pub(crate)` and
/// never exported to the RPC tier.
///
/// A clone is a mailbox address, not a share of the store: every clone (the
/// engine's field, the [`LocalPendingTx`](super::local_pending_tx) spend-gate
/// clone, the stake engine's pinner) reaches the one actor, and the store
/// closes when that actor stops, however many clones are alive. Recovery
/// from a poisoned client happens inside the actor ([`Self::recover`]), so
/// no clone ever needs repointing. *Records-was (until 2026-11-02):* the
/// handle wrapped the `ActorRef` in a shared swappable cell and carried a
/// `WriterRecovery` (a share of the store), so that an engine-side respawn
/// could resume a writer over the same store and swap the fresh actor in for
/// every clone.
#[derive(Clone)]
pub(crate) struct CurveTreeHandle {
    /// The actor's mailbox.
    actor: ActorRef<CurveTreeActor>,
}

impl CurveTreeHandle {
    /// Spawn the [`CurveTreeActor`] over an already-opened [`CurveTreeClient`],
    /// returning the handle.
    ///
    /// **Runtime hosting — require-ambient.** Like
    /// [`KeyEngineHandle::spawn`](super::key_actor::KeyEngineHandle::spawn), a
    /// [`CurveTreeActor`] is an async task that *requires* a Tokio runtime;
    /// `spawn` asserts an ambient runtime rather than hosting an engine-owned
    /// one (the rejected drop-panic / `shutdown_background` shape). Production
    /// (wallet-RPC / async CLI / GUI) calls into `Engine::create` from inside
    /// its runtime; tests use `#[tokio::test]`.
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime; the message names the fix.
    pub(crate) fn spawn(client: CurveTreeClient) -> Self {
        Self {
            actor: Self::spawn_actor(client),
        }
    }

    /// Spawn the actor task over `client`, asserting an ambient runtime first.
    /// The single actor-spawning chokepoint, so the require-ambient contract
    /// holds wherever a handle is made.
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime; the message names the fix.
    fn spawn_actor(client: CurveTreeClient) -> ActorRef<CurveTreeActor> {
        assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "CurveTreeHandle::spawn requires an ambient Tokio runtime: the \
             CurveTreeActor is an async task and must be spawned inside a \
             runtime. Production (wallet-RPC / async CLI / GUI) calls \
             Engine::create from inside its runtime; tests must use \
             #[tokio::test] (or wrap the call in one). See \
             CT5_ENGINE_WIRING.md §3.1."
        );
        CurveTreeActor::spawn(client)
    }

    /// The actor's mailbox, for one `ask`.
    fn actor_ref(&self) -> &ActorRef<CurveTreeActor> {
        &self.actor
    }

    /// Rebuild a poisoned client in place, inside the actor ([`Recover`]).
    /// The engine sends it after a failed `ask` returned
    /// [`ClientError::Poisoned`], then retries. The file is not reopened and
    /// no second writer exists at any point; the actor and every clone of this
    /// handle stay as they were.
    ///
    /// # Errors
    ///
    /// [`CurveTreeHandleError::Client`] when the store no longer resumes
    /// (pruned or corrupt), and [`CurveTreeHandleError::Unavailable`] on a
    /// stopped actor.
    pub(crate) async fn recover(&self) -> Result<(), CurveTreeHandleError> {
        self.actor_ref()
            .ask(Recover)
            .await
            .map_err(collapse_send_error)
    }

    /// Stop the actor and wait until its `on_stop` has run. When this returns
    /// the client has been dropped and the redb file is closed, so the store
    /// can be reopened at once, by this process or another. Messages already
    /// queued are handled first (a graceful stop);
    /// an `ask` sent afterwards, through any clone, is
    /// [`CurveTreeHandleError::Unavailable`]. Idempotent: on an actor that
    /// has already stopped, it returns once the stop has completed.
    pub(crate) async fn shutdown(&self) {
        // `stop_gracefully` errs only when the actor is no longer running,
        // which is a stop already under way; the wait below covers both.
        if let Err(not_running) = self.actor.stop_gracefully().await {
            tracing::debug!(?not_running, "curve-tree actor already stopping");
        }
        // `wait_for_shutdown_result`, not `wait_for_shutdown`: the latter
        // resolves when the mailbox closes, before `on_stop` has dropped the
        // client (module docs).
        if let Err(hook) = self.actor.wait_for_shutdown_result().await {
            tracing::warn!(?hook, "the curve-tree actor's stop hook failed");
        }
    }

    /// Ingest one block's leaves at `height` (must equal the client's ingested
    /// tip plus one). Routes through the actor `ask`; on a stopped actor it
    /// returns [`CurveTreeHandleError::Unavailable`].
    pub(crate) async fn ingest(
        &self,
        height: BlockHeight,
        txs: Arc<Vec<OwnedTxLeaves>>,
    ) -> Result<(), CurveTreeHandleError> {
        self.actor_ref()
            .ask(IngestBlock { height, txs })
            .await
            .map_err(collapse_send_error)
    }

    /// Roll the client back to `fork_height` on a reorg.
    pub(crate) async fn rollback_to_fork(
        &self,
        fork_height: BlockHeight,
    ) -> Result<(), CurveTreeHandleError> {
        self.actor_ref()
            .ask(RollbackToFork { fork_height })
            .await
            .map_err(collapse_send_error)
    }

    /// Read the tree's authoritative resume cursor
    /// ([`CurveTreeClient::ingested_tip_height`]): the last ingested height, or
    /// `None` when fresh. The forward / backfill driver calls this every
    /// iteration to compute its next height (`tip + 1`, `BlockHeight::from_raw(0)` when
    /// `None`) instead of holding a local frontier (D2). On a stopped actor it
    /// returns [`CurveTreeHandleError::Unavailable`]; the read itself never
    /// produces [`CurveTreeHandleError::Client`].
    pub(crate) async fn ingested_tip_height(
        &self,
    ) -> Result<Option<BlockHeight>, CurveTreeHandleError> {
        self.actor_ref()
            .ask(IngestedTipHeight)
            .await
            .map_err(collapse_send_error)
    }

    /// Pin a persona's serve-set (SH-2) in this actor's store — see
    /// [`PinServeSet`].
    ///
    /// # Errors
    ///
    /// [`CurveTreeHandleError::Client`] wrapping the store's refusal (an
    /// unrepresentable shard id, or a store fault), and
    /// [`CurveTreeHandleError::Unavailable`] on a stopped actor.
    pub(crate) async fn pin_serve_set(
        &self,
        shard_ids: Vec<u64>,
        release_ids: Vec<u64>,
    ) -> Result<PinServeSetReply, CurveTreeHandleError> {
        self.actor_ref()
            .ask(PinServeSet {
                shard_ids,
                release_ids,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Which store this handle's actor owns: the actor's id, fixed for its
    /// life. An in-place rebuild keeps the actor and the store; a new store
    /// would be a new actor. The serving host's witness checks every report
    /// and reading against it.
    pub(crate) fn store_identity(&self) -> u64 {
        self.actor.id().sequence_id()
    }

    /// Read the store facts the serving host's witness checks — see
    /// [`ReadStoreFacts`].
    ///
    /// # Errors
    ///
    /// [`CurveTreeHandleError::Client`] wrapping a store fault, and
    /// [`CurveTreeHandleError::Unavailable`] on a stopped actor.
    pub(crate) async fn store_facts(
        &self,
        claimed: Vec<u64>,
    ) -> Result<StoreFactsReply, CurveTreeHandleError> {
        self.actor_ref()
            .ask(ReadStoreFacts { claimed })
            .await
            .map_err(collapse_send_error)
    }

    /// Run the corpus integrity scan — see [`ScanPrunedFrozenSegments`].
    ///
    /// # Errors
    ///
    /// [`CurveTreeHandleError::Client`] wrapping a store fault, and
    /// [`CurveTreeHandleError::Unavailable`] on a stopped actor.
    pub(crate) async fn pruned_frozen_segments(&self) -> Result<Vec<u64>, CurveTreeHandleError> {
        self.actor_ref()
            .ask(ScanPrunedFrozenSegments)
            .await
            .map_err(collapse_send_error)
    }

    /// Declare the CompleteTree serving posture and read the prefix it
    /// vouches for — see [`PinCompleteTreePrefix`] for why both halves ride
    /// one message and why the handler invocation is the atomicity unit.
    ///
    /// # Errors
    ///
    /// [`CurveTreeHandleError::Client`] wrapping a store fault, and
    /// [`CurveTreeHandleError::Unavailable`] on a stopped actor.
    pub(crate) async fn pin_complete_tree_prefix(
        &self,
    ) -> Result<PinCompleteTreePrefixReply, CurveTreeHandleError> {
        self.actor_ref()
            .ask(PinCompleteTreePrefix)
            .await
            .map_err(collapse_send_error)
    }

    /// §3.3 ingest-time integrity verify (CT-5b): require the reconstructed
    /// root at `height` to byte-equal the consensus header-committed
    /// `expected_root`. A divergence collapses (via the handler) to
    /// [`ClientError::RootMismatch`]; a stopped actor to
    /// [`CurveTreeHandleError::Unavailable`]. This is the production root read —
    /// the engine calls it after each ingest so the ledger never advances past
    /// a tree state the wallet cannot reproduce against the header (O5).
    pub(crate) async fn verify_root(
        &self,
        height: BlockHeight,
        expected_root: CurveTreeRoot,
    ) -> Result<(), CurveTreeHandleError> {
        self.actor_ref()
            .ask(VerifyRoot {
                height,
                expected_root,
            })
            .await
            .map_err(collapse_send_error)
    }

    /// Test-only: stop the underlying actor and wait for its task to end,
    /// simulating a fail-stop (the `on_panic → Break` path) without a real
    /// panic. After this returns the actor is gone and every handle call
    /// collapses to [`CurveTreeHandleError::Unavailable`], for good.
    #[cfg(test)]
    pub(crate) async fn kill_and_wait_for_test(&self) {
        let actor = self.actor_ref();
        actor.kill();
        actor.wait_for_shutdown().await;
    }

    /// Test-only: poison the actor's client, as a post-commit rollback
    /// failure would, so [`Self::recover`] can be driven.
    #[cfg(test)]
    pub(crate) async fn poison_for_test(&self) {
        self.actor_ref()
            .ask(PoisonForTest)
            .await
            .map_err(collapse_send_error)
            .expect("the actor is running");
    }

    /// Read the reconstructed root **and** depth at `height`
    /// ([`CurveTreeClient::root_and_depth_at`]) through the actor (CT-5c Q1).
    /// The send path binds the root into the
    /// [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock) and uses the depth
    /// to size the FCMP++ proof weight for fee estimation *before* assembling
    /// any path. Both are pinned to one drained leaf count, so they describe the
    /// same tree state. On a stopped actor returns
    /// [`CurveTreeHandleError::Unavailable`]; a height beyond the ingested tip
    /// surfaces the client's `ReferenceBeyondIngestedTip`.
    pub(crate) async fn reference_root_and_depth(
        &self,
        height: BlockHeight,
    ) -> Result<([u8; 32], u8), CurveTreeHandleError> {
        self.actor_ref()
            .ask(RootAndDepthAt { height })
            .await
            .map_err(collapse_send_error)
    }

    /// Assemble every membership path for one transaction in a single actor
    /// round-trip ([`AssembleTx`], CT-5c T3 / Q2). `inputs` are the owned
    /// outputs in transaction input order; the reply preserves that order, every
    /// path sharing the one `reference` (C1). The whole batch assembles under a
    /// single handler invocation, so no ingest/rollback interleaves (E1). On a
    /// stopped actor returns [`CurveTreeHandleError::Unavailable`]; an
    /// over-length batch or a per-input failure (root mismatch, undrained,
    /// identity mismatch) surfaces as [`CurveTreeHandleError::Client`].
    pub(crate) async fn assemble_tx(
        &self,
        reference: ReferenceBlock,
        inputs: Vec<AssembleInput>,
    ) -> Result<Vec<AssembledPath>, CurveTreeHandleError> {
        self.actor_ref()
            .ask(AssembleTx { reference, inputs })
            .await
            .map_err(collapse_send_error)
    }

    /// Replace the expected outputs and register the held pairs, in that
    /// order, in one round-trip ([`OfferOwned`]).
    pub(crate) async fn offer_owned(
        &self,
        expected: Vec<shekyl_curve_tree::ExpectedOutput>,
        outputs: Vec<(shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey)>,
    ) -> Result<shekyl_curve_tree::OwnershipSync, CurveTreeHandleError> {
        self.actor_ref()
            .ask(OfferOwned { expected, outputs })
            .await
            .map_err(collapse_send_error)
    }

    /// Register owned outputs with the tree, reconciling once if any is owed,
    /// without replacing the expectation set ([`SyncOwned`]).
    ///
    /// The refresh uses [`Self::offer_owned`]. This is the entry that leaves
    /// the expectation set in place. Its callers are `cfg(test)`; the lib
    /// target does not compile them.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "pair registration that must not replace expectations; its callers are cfg(test)"
        )
    )]
    pub(crate) async fn sync_owned(
        &self,
        outputs: Vec<(shekyl_curve_tree::Gindex, shekyl_curve_tree::OneTimePubkey)>,
    ) -> Result<shekyl_curve_tree::OwnershipSync, CurveTreeHandleError> {
        self.actor_ref()
            .ask(SyncOwned { outputs })
            .await
            .map_err(collapse_send_error)
    }
}

// The actor's contract tests live beside this file, as `merge.rs`'s do: the
// production half is the actor, its messages and the handle, and keeping the
// tests in it had pushed the file past the engine's god-file line.
#[cfg(test)]
#[path = "curve_tree_actor_tests.rs"]
mod tests;
