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
//! 2. Respawn-on-poison (R1-Q4) runs **engine-side, after the failed `ask`
//!    returns** (CT-5a §3.1 / commit 5) — never inside a handler awaited under
//!    the guard.
//!
//! Corollary: *the curve-tree actor never acquires the engine lock; the engine
//! may hold its lock across a curve-tree `ask`.*
//!
//! # Fail-stop, not supervised
//!
//! A panic in a handler runs [`Actor::on_panic`], which returns
//! [`ControlFlow::Break`] so the actor stops rather than restarts. After a
//! stop, every [`CurveTreeHandle`] call collapses the kameo transport failure
//! into [`CurveTreeHandleError::Unavailable`]; the engine's R1-Q4 respawn
//! ([`CurveTreeHandle::respawn`]: drop + reopen the client in a fresh task) is
//! the recovery, and it runs engine-side per clause 2. Because the handle wraps
//! a **shared swappable cell** ([`Arc`]`<`[`Mutex`]`<ActorRef>>`), the respawn
//! swaps the fresh actor in for **every** clone of the handle at once — the
//! engine's field and the [`LocalPendingTx`](super::local_pending_tx) spend-gate
//! clone alike — so recovery is whole, not a partial heal that leaves the spend
//! path bound to the dead actor.
//!
//! [`docs/design/CT5_ENGINE_WIRING.md`]: ../../../../../docs/design/CT5_ENGINE_WIRING.md

use std::ops::ControlFlow;
use std::path::Path;
use std::sync::{Arc, Mutex};

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_curve_tree::{BlockHeight, BlockLeaves, ClientError, CurveTreeClient, TxLeafInputs};

use crate::scan::OwnedTxLeaves;

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
    client: CurveTreeClient,
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
        Ok(Self { client })
    }

    /// Fail-stop on panic. This is the kameo default, overridden explicitly so
    /// the no-restart posture is locked at the type layer rather than inherited
    /// from a framework default that could change under a dependency bump. The
    /// engine-side R1-Q4 respawn (clause 2) is the recovery, not a supervisor
    /// restart.
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    // No `on_stop`: the curve-tree client carries no secret bytes (contrast
    // `KeyActor::on_stop`, which wipes `AllKeysBlob`). The redb database flushes
    // and closes through `CurveTreeClient`'s own `Drop` at task-end.
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
    /// a height's leaves while *retaining* its own reference: a
    /// respawn-recoverable `ask` failure (actor fail-stop / poison) consumes
    /// this message, but the driver's `Arc` survives for the
    /// respawn-and-retry resend (R1-Q4) — no deep clone, no lost leaf set.
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

/// Actor message for the §3.3 ingest-time integrity verify (CT-5b): reconstruct
/// the curve-tree root at `height` and require it to byte-equal the consensus
/// header-committed `expected_root`. Replies [`ClientError::RootMismatch`] on
/// divergence — the lying-daemon (O5) defense: the wallet refuses to advance
/// past a tree state it ingested but cannot reproduce against the header the
/// producer claimed.
///
/// This is the compare sibling of the [`RootAt`] read-back — both are
/// production root operations (`RootAt` returns the reconstructed root,
/// `VerifyRoot` compares it against an expected value). It is keyed by
/// `(height, expected_root)` rather than a full
/// [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock) because ingest has no
/// `block_hash` to anchor — the header root is the only field
/// [`CurveTreeClient::verify_root`] consults, so this mirrors its compare
/// without fabricating the unused field.
pub(crate) struct VerifyRoot {
    /// The height whose reconstructed root to check (must be `<=` ingested tip).
    pub height: BlockHeight,
    /// The consensus header-committed root the reconstruction must match.
    pub expected_root: [u8; 32],
}

/// Actor message reading [`CurveTreeClient::root_at`]: the reconstructed
/// curve-tree root as of `height`.
///
/// The **send-time re-derivation** of the reference-height root (CT-5b §3.2):
/// the reference root is never persisted (derive>hold, R1-Q6) — it is
/// reconstructed here at send time and bound into the
/// [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock) the proof anchors to.
/// Also the read-back the CT-5a commit-6 oracle KAT (in `refresh.rs`'s
/// `start_refresh_integration_tests`) uses to assert the engine ingest path
/// reproduces the consensus header root at every height.
pub(crate) struct RootAt {
    /// The reference height whose reconstructed root to read.
    pub height: BlockHeight,
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
                leaf_hash_blob: tx.leaf_hash_blob.as_deref(),
                outputs: tx.outputs.as_slice(),
            })
            .collect();
        self.client.ingest_block(BlockLeaves {
            height: msg.height,
            txs: &txs,
        })
    }
}

impl Message<RollbackToFork> for CurveTreeActor {
    type Reply = Result<(), ClientError>;

    async fn handle(
        &mut self,
        msg: RollbackToFork,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.client.rollback_to_fork(msg.fork_height)
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
        Ok(self.client.ingested_tip_height())
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
        let got = self.client.root_at(msg.height)?;
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

impl Message<RootAt> for CurveTreeActor {
    type Reply = Result<[u8; 32], ClientError>;

    async fn handle(&mut self, msg: RootAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.client.root_at(msg.height)
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
/// [`Unavailable`](CurveTreeHandleError::Unavailable), which is terminal until
/// the engine-side R1-Q4 respawn (clause 2).
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
    /// [`key_actor`](super::key_actor) §4.4 T4 note). Every case is
    /// `recoverable_by_respawn` and terminal until the engine respawns the
    /// actor.
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
/// field. Wraps the actor's [`ActorRef`] in a **shared swappable cell** (§3.1).
/// It is `pub(crate)` and never exported to the RPC tier.
///
/// # Why a shared cell, not a bare [`ActorRef`] clone
///
/// The R1-Q4 respawn ([`CurveTreeHandle::respawn`]) drops the dead actor and spawns a fresh
/// one over the reopened store. If the handle were a bare `ActorRef` clone, the
/// respawn could only replace the *one* field it was called through (the engine's
/// `curve_tree`); every other clone — notably the
/// [`LocalPendingTx`](super::local_pending_tx) spend-gate clone — would keep
/// pointing at the dead actor and fail every call forever. That is a *partial
/// heal*: refresh recovers, spends silently stay broken. Wrapping the `ActorRef`
/// in an [`Arc`]`<`[`Mutex`]`<…>>` makes the respawn swap the fresh actor in for
/// **all** clones at once, so recovery is whole. The mutex is held only to clone
/// or replace the inner `ActorRef` (never across an `.await`).
/// Upper bound on how long [`CurveTreeHandle::respawn`] retries the reopen
/// while the prior actor's redb single-writer lock is released. Past this the
/// reopen error is surfaced (genuinely corrupt or externally-held store). See
/// the `respawn` "Reopen-after-shutdown race" note for why a grace window is
/// needed at all.
const REOPEN_LOCK_RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Poll interval for the [`CurveTreeHandle::respawn`] reopen retry.
const REOPEN_LOCK_RELEASE_POLL: std::time::Duration = std::time::Duration::from_millis(2);

#[derive(Clone)]
pub(crate) struct CurveTreeHandle {
    /// Shared, swappable strong reference to the curve-tree actor's mailbox.
    /// All clones of this handle share the one cell, so [`Self::respawn`]
    /// propagates the fresh actor to every holder. `ActorRef` is
    /// `Clone + Send + Sync`; the [`Mutex`] guard is never held across `.await`.
    actor: Arc<Mutex<ActorRef<CurveTreeActor>>>,
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
            actor: Arc::new(Mutex::new(Self::spawn_actor(client))),
        }
    }

    /// Spawn the actor task over `client`, asserting an ambient runtime first.
    /// The single actor-spawning chokepoint shared by [`Self::spawn`] (initial
    /// open) and [`Self::respawn`] (R1-Q4 reopen), so the require-ambient
    /// contract holds on both paths.
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

    /// Snapshot the current actor reference. Locks the shared cell only long
    /// enough to clone the (cheap, `Arc`-backed) [`ActorRef`], so the guard is
    /// never held across the subsequent `.await` — the lock-ordering discipline
    /// that keeps the curve-tree path deadlock-free (§3.1).
    ///
    /// A poisoned mutex means a prior panic while the lock was held; recover the
    /// inner [`ActorRef`] so respawn can still swap in a fresh actor rather than
    /// taking down the wallet process on the next ingest.
    fn actor_ref(&self) -> ActorRef<CurveTreeActor> {
        self.actor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Open (or create + resume) the persistent [`CurveTreeClient`] at `path`
    /// and spawn the actor over it — the single open-then-spawn entry point.
    ///
    /// [`CurveTreeClient::open`] resumes from the store's contents with **no
    /// genesis replay** (`CT3_SYNC.md` §3.1 / R1-Q2), so this is cheap on an
    /// already-synced store. The drop-and-reopen *respawn* half of R1-Q4 is
    /// [`Self::respawn`], which reuses the same open + spawn but swaps the result
    /// into the existing shared cell rather than minting a new handle.
    ///
    /// `assemble` uses this for the initial open: `path` is the curve-tree store
    /// sibling of the wallet files
    /// ([`curve_tree_store_path_from`](shekyl_engine_file::paths::curve_tree_store_path_from)).
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime (see [`Self::spawn`]).
    pub(crate) fn open_and_spawn(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let client = CurveTreeClient::open(path)?;
        Ok(Self::spawn(client))
    }

    /// Drop-and-reopen the actor over the persistent store at `path` — the
    /// engine-side R1-Q4 respawn body (§3.3), run engine-side after a failed
    /// `ask` returns (clause 2), never inside a handler under the engine guard.
    ///
    /// Steps, in order, so the redb single-writer lock is free before the reopen:
    ///
    /// 1. [`ActorRef::kill`] the current actor (idempotent on an
    ///    already-fail-stopped one) and [`ActorRef::wait_for_shutdown`] — the
    ///    task end drops the old [`CurveTreeClient`], releasing the redb file.
    /// 2. [`CurveTreeClient::open`] the same `path` (no genesis replay; resumes
    ///    from the persisted cursor — D2 resume-from-store), then spawn a fresh
    ///    actor over it.
    /// 3. Swap the fresh [`ActorRef`] into the shared cell, so this handle **and
    ///    every clone** observe the new actor.
    ///
    /// Returns the [`CurveTreeClient::open`] error if the reopen fails past the
    /// [`REOPEN_LOCK_RELEASE_TIMEOUT`] grace window (e.g. a genuinely corrupt or
    /// externally-held store). The caller decides recovery: the engine's single
    /// respawn-and-retry is
    /// [`Engine::ingest_scan_result_with_respawn`](super::Engine::ingest_scan_result_with_respawn);
    /// the bounded-retry-then-surface escalation that distinguishes a transient
    /// hiccup from a permanently corrupt store (O3-sub) is CT-5d.
    ///
    /// # Reopen-after-shutdown race
    ///
    /// [`ActorRef::wait_for_shutdown`] resolves when the actor's mailbox closes,
    /// but kameo returns the actor *value* as the task's output and drops it
    /// **after** that point (`spawn.rs` `run_actor_lifecycle`). The old
    /// [`CurveTreeClient`] — and its redb single-writer lock — may therefore not
    /// be released the instant `wait_for_shutdown` returns. The reopen is retried
    /// on a short poll until the lock is free, bounded by
    /// [`REOPEN_LOCK_RELEASE_TIMEOUT`] so a store that never frees up surfaces its
    /// error rather than spinning forever.
    pub(crate) async fn respawn(&self, path: impl AsRef<Path>) -> Result<(), ClientError> {
        let old = self.actor_ref();
        old.kill();
        old.wait_for_shutdown().await;

        let path = path.as_ref();
        let deadline = std::time::Instant::now() + REOPEN_LOCK_RELEASE_TIMEOUT;
        let client = loop {
            match CurveTreeClient::open(path) {
                Ok(client) => break client,
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(REOPEN_LOCK_RELEASE_POLL).await;
                }
            }
        };

        let fresh = Self::spawn_actor(client);
        *self
            .actor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
        Ok(())
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
    /// iteration to compute its next height (`tip + 1`, `BlockHeight(0)` when
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
        expected_root: [u8; 32],
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
    /// collapses to [`CurveTreeHandleError::Unavailable`] until a
    /// [`Self::respawn`]; the redb lock is released (task drop), so the reopen
    /// can take it.
    #[cfg(test)]
    pub(crate) async fn kill_and_wait_for_test(&self) {
        let actor = self.actor_ref();
        actor.kill();
        actor.wait_for_shutdown().await;
    }

    /// Read the reconstructed curve-tree root as of `height`
    /// ([`CurveTreeClient::root_at`]) through the actor — the CT-5b §3.2
    /// send-time re-derivation of the reference-height root (the root is never
    /// persisted; reconstructed here and bound into the
    /// [`ReferenceBlock`](shekyl_curve_tree::ReferenceBlock)). Also the read-back
    /// the CT-5a commit-6 oracle KAT uses to assert the ingest path reproduces
    /// the consensus header root at every height. On a stopped actor returns
    /// [`CurveTreeHandleError::Unavailable`]; a height beyond the ingested tip
    /// surfaces the client's `ReferenceBeyondIngestedTip` via
    /// [`CurveTreeHandleError::Client`].
    pub(crate) async fn root_at(
        &self,
        height: BlockHeight,
    ) -> Result<[u8; 32], CurveTreeHandleError> {
        self.actor_ref()
            .ask(RootAt { height })
            .await
            .map_err(collapse_send_error)
    }
}

// ---------------------------------------------------------------------------
// Tests (CT-5a commit 1: scaffold + message protocol + structural invariant)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! CT-5a commit-1 contract tests for [`CurveTreeActor`] / [`CurveTreeHandle`].
    //! These pin the actor scaffold and message protocol; the behavioral
    //! ingest / rollback KATs (root-matches-the-CT-2-oracle, reorg, respawn)
    //! land in later commits where the real `ScannableBlock → BlockLeaves`
    //! decode and fixtures exist.

    use super::*;

    use tempfile::TempDir;

    /// Open a fresh, empty [`CurveTreeClient`] over a tempdir-backed store.
    fn fresh_client() -> (TempDir, CurveTreeClient) {
        let dir = TempDir::new().expect("tempdir");
        let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
            .expect("open fresh curve-tree client");
        (dir, client)
    }

    /// **Lock-ordering clause 1 (§3.1 / E2), enforced mechanically.** The
    /// actor's only construction input is the [`CurveTreeClient`]: `on_start`
    /// receives exactly [`Actor::Args`] plus a [`WeakActorRef`] (no engine
    /// state), so pinning `Args = CurveTreeClient` makes "reach back for engine
    /// state" a compile error — a field that needed engine state would have to
    /// enter through `Args` and break this bound. A future "let the actor read
    /// engine config for X" change fails to compile here, on this rule, rather
    /// than passing tests until a deadlock interleaving in production.
    #[test]
    fn actor_constructed_from_only_the_client() {
        fn assert_args_is_client<A: Actor<Args = CurveTreeClient>>() {}
        assert_args_is_client::<CurveTreeActor>();
    }

    /// kameo requires the actor and its messages to be `Send`. (The replies are
    /// `Result<(), ClientError>`; `ClientError: Send` is exercised by the
    /// `ask` round-trips in later commits.)
    #[test]
    fn actor_and_messages_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CurveTreeActor>();
        assert_send::<IngestBlock>();
        assert_send::<RollbackToFork>();
        assert_send::<IngestedTipHeight>();
        assert_send::<VerifyRoot>();
        assert_send::<RootAt>();
        assert_send::<OwnedTxLeaves>();
    }

    /// Require-ambient spawn contract: with no ambient Tokio runtime,
    /// [`CurveTreeHandle::spawn`] panics with the contract message before any
    /// actor task is scheduled. A plain `#[test]` precisely because it must run
    /// with no ambient runtime.
    #[test]
    #[should_panic(expected = "requires an ambient Tokio runtime")]
    fn spawn_without_ambient_runtime_panics() {
        let (_dir, client) = fresh_client();
        let _handle = CurveTreeHandle::spawn(client);
    }

    /// The actor spawns over a fresh client and is alive on an ambient runtime.
    #[tokio::test]
    async fn spawns_and_is_alive() {
        let (_dir, client) = fresh_client();
        let handle = CurveTreeHandle::spawn(client);
        assert!(handle.actor_ref().is_alive(), "actor is alive after spawn");
    }

    /// **R1-Q4 respawn happy path + shared-cell propagation (O3, §3.3).** The
    /// load-bearing KAT for commit 5: a fail-stopped actor is healed by
    /// [`CurveTreeHandle::respawn`], which (a) resumes from the persisted store
    /// cursor with no genesis replay (D2 resume-from-store), and (b) swaps the
    /// fresh actor into the **shared cell** so a clone taken *before* the
    /// respawn — modelling the [`LocalPendingTx`](super::super::local_pending_tx)
    /// spend-gate clone — observes the new actor too. Without the shared cell
    /// the clone would keep pointing at the dead actor and fail forever (the
    /// partial-heal hazard this handle shape forecloses).
    ///
    /// Blocks are empty-leaf (no coinbase) — accepted by `ingest_block`, which
    /// advances the height cursor regardless of leaf count; the same shape the
    /// merge-path reorg KAT relies on. Behavioral leaf/root correctness is the
    /// CT-2-oracle KAT (commit 6) / Tier-B completeness (CT-5c), not here.
    #[tokio::test]
    async fn respawn_resumes_from_store_and_propagates_to_clones() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("curve_tree.redb");
        let client = CurveTreeClient::open(&path).expect("open fresh client");
        let handle = CurveTreeHandle::spawn(client);

        // Ingest empty blocks 0..=2 → persisted cursor at height 2.
        for h in 0..=2 {
            handle
                .ingest(BlockHeight(h), Arc::new(Vec::new()))
                .await
                .expect("ingest empty block");
        }
        assert_eq!(
            handle.ingested_tip_height().await.expect("cursor read"),
            Some(BlockHeight(2)),
            "three consecutive ingests leave the cursor at height 2"
        );

        // A clone taken BEFORE the respawn — the spend-gate-clone analogue.
        let clone = handle.clone();

        // Simulate the fail-stop: both the original and the pre-respawn clone
        // now collapse to Unavailable (they share the one — now dead — actor).
        handle.kill_and_wait_for_test().await;
        assert!(
            matches!(
                handle.ingested_tip_height().await,
                Err(CurveTreeHandleError::Unavailable)
            ),
            "a fail-stopped actor makes the original handle Unavailable"
        );
        assert!(
            matches!(
                clone.ingested_tip_height().await,
                Err(CurveTreeHandleError::Unavailable)
            ),
            "the pre-respawn clone shares the dead actor and is Unavailable too"
        );

        // Respawn via the original handle: reopens the same store.
        handle
            .respawn(&path)
            .await
            .expect("respawn reopens the store");

        // (a) resume-from-store: the persisted cursor survived the drop+reopen.
        assert_eq!(
            handle.ingested_tip_height().await.expect("cursor read"),
            Some(BlockHeight(2)),
            "respawn resumes from the persisted store cursor (no genesis replay)"
        );
        // (b) propagation: the clone taken before the respawn observes the
        // fresh actor through the shared cell — whole heal, not partial.
        assert_eq!(
            clone.ingested_tip_height().await.expect("cursor read"),
            Some(BlockHeight(2)),
            "the pre-respawn clone observes the respawned actor via the shared cell"
        );
        // And ingest resumes at cursor+1 through the clone.
        clone
            .ingest(BlockHeight(3), Arc::new(Vec::new()))
            .await
            .expect("ingest resumes at cursor+1 after respawn");
        assert_eq!(
            handle.ingested_tip_height().await.expect("cursor read"),
            Some(BlockHeight(3)),
            "post-respawn ingest advances the shared cursor seen by every clone"
        );
    }

    /// Cursor-read `ask` round-trip on a fresh client returns `None` — the
    /// `BlockHeight(0)` resume point for a from-genesis ingest (D2). This pins
    /// the transport + reply type + collapse for [`IngestedTipHeight`]; the
    /// non-`None` (post-ingest, post-rollback) cursor behavior is proven at the
    /// client level (`ingested_tip_height_getter_tracks_cursor`) and exercised
    /// end-to-end once the merge-driven ingest fixtures land.
    #[tokio::test]
    async fn cursor_read_on_fresh_client_is_none() {
        let (_dir, client) = fresh_client();
        let handle = CurveTreeHandle::spawn(client);
        let tip = handle
            .ingested_tip_height()
            .await
            .expect("cursor read on a live actor");
        assert_eq!(tip, None, "a fresh client has no ingested tip");
    }
}
