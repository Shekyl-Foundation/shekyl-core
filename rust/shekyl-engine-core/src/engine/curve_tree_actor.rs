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
//! (drop + reopen the client in a fresh task) is the recovery, and it runs
//! engine-side per clause 2.
//!
//! [`docs/design/CT5_ENGINE_WIRING.md`]: ../../../../../docs/design/CT5_ENGINE_WIRING.md

use std::ops::ControlFlow;
use std::path::Path;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_curve_tree::{
    BlockHeight, BlockLeaves, ClientError, CurveTreeClient, RawOutput, TxLeafInputs,
};

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
#[allow(dead_code)] // CT-5a wires the handle into Engine in a later commit; today: tests only.
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

/// Owned, `Send` mirror of [`TxLeafInputs`] for the [`IngestBlock`] message.
///
/// [`BlockLeaves`] / [`TxLeafInputs`] borrow (`leaf_hash_blob: Option<&[u8]>`,
/// `outputs: &[RawOutput]`); a `kameo` message must own its payload (`Send +
/// 'static`). The producer materializes these owned vecs (CT-5a commit 3), and
/// the [`IngestBlock`] handler re-borrows them into a [`BlockLeaves`] inside the
/// actor task.
#[allow(dead_code)] // populated by the producer in a later commit; today: constructed by tests.
pub(crate) struct OwnedTxLeaves {
    /// Whether this is the block's coinbase (miner) transaction.
    pub is_miner: bool,
    /// The validated `tx_extra 0x07` curve-tree leaf-hash blob, if present.
    pub leaf_hash_blob: Option<Vec<u8>>,
    /// The transaction's outputs in on-chain order.
    pub outputs: Vec<RawOutput>,
}

/// Actor message for [`CurveTreeClient::ingest_block`]: append one block's
/// leaves at the next consecutive height. Carries [`BlockHeight`] across the
/// actor boundary (not an unwrapped `u64`) — the CT-3a P5 cross-seam typing.
#[allow(dead_code)] // dispatched by the merge path in a later commit; today: tests only.
pub(crate) struct IngestBlock {
    /// The block's height (must equal the client's ingested-tip + 1).
    pub height: BlockHeight,
    /// The block's transactions in block order (coinbase first).
    pub txs: Vec<OwnedTxLeaves>,
}

/// Actor message for [`CurveTreeClient::rollback_to_fork`]: drop all leaves
/// after `fork_height` on a reorg. Carries [`BlockHeight`] across the boundary.
#[allow(dead_code)] // dispatched by the reorg path in a later commit; today: tests only.
pub(crate) struct RollbackToFork {
    /// The last height that survives the reorg; leaves above it are dropped.
    pub fork_height: BlockHeight,
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

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Error from a [`CurveTreeHandle`] call.
///
/// Mirrors the [`KeyEngineHandle`](super::key_actor::KeyEngineHandle) send-error
/// collapse: a handler error carries the real [`ClientError`] the client
/// returned (e.g. [`ClientError::NonConsecutiveBlockHeight`],
/// [`ClientError::Poisoned`]); every transport failure against a stopped actor
/// maps to [`Unavailable`](CurveTreeHandleError::Unavailable), which is
/// terminal until the engine-side R1-Q4 respawn (clause 2).
#[derive(Debug)]
#[allow(dead_code)] // surfaced by the merge/reorg paths in later commits; today: tests only.
pub(crate) enum CurveTreeHandleError {
    /// The client returned an error inside the handler.
    Client(ClientError),
    /// The actor is not running (fail-stopped or stopped). Terminal until the
    /// engine respawns the actor.
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
/// field. Wraps the actor's [`ActorRef`] (§3.1). It is `pub(crate)` and never
/// exported to the RPC tier.
#[derive(Clone)]
#[allow(dead_code)] // constructed once Engine wiring lands (commit 2); today: tests only.
pub(crate) struct CurveTreeHandle {
    /// Strong reference to the curve-tree actor's mailbox. `Clone + Send + Sync`.
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
    #[allow(dead_code)] // CT-5a wires this into Engine in commit 2; today: tests only.
    pub(crate) fn spawn(client: CurveTreeClient) -> Self {
        assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "CurveTreeHandle::spawn requires an ambient Tokio runtime: the \
             CurveTreeActor is an async task and must be spawned inside a \
             runtime. Production (wallet-RPC / async CLI / GUI) calls \
             Engine::create from inside its runtime; tests must use \
             #[tokio::test] (or wrap the call in one). See \
             CT5_ENGINE_WIRING.md §3.1."
        );
        let actor = CurveTreeActor::spawn(client);
        Self { actor }
    }

    /// Open (or create + resume) the persistent [`CurveTreeClient`] at `path`
    /// and spawn the actor over it — the single open-then-spawn entry point.
    ///
    /// [`CurveTreeClient::open`] resumes from the store's contents with **no
    /// genesis replay** (`CT3_SYNC.md` §3.1 / R1-Q2), so this is cheap on an
    /// already-synced store and is also the **reopen** half of the R1-Q4
    /// drop-and-reopen respawn: the engine drops the dead [`CurveTreeHandle`]
    /// (its last [`ActorRef`] clone going away stops the fail-stopped actor and
    /// drops the old [`CurveTreeClient`], releasing the redb file), then calls
    /// this against the same `path` to reattach to the persisted state. The
    /// caller (commit 5's reorg/poison path) is responsible for ensuring the
    /// prior actor has fully stopped before reopening, so the redb single-writer
    /// lock is free.
    ///
    /// `assemble` uses this for the initial open: `path` is the curve-tree store
    /// sibling of the wallet files
    /// ([`curve_tree_store_path_from`](shekyl_engine_file::paths::curve_tree_store_path_from)).
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime (see [`Self::spawn`]).
    #[allow(dead_code)] // reopen half is wired by the R1-Q4 respawn in commit 5.
    pub(crate) fn open_and_spawn(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let client = CurveTreeClient::open(path)?;
        Ok(Self::spawn(client))
    }

    /// Ingest one block's leaves at `height` (must equal the client's ingested
    /// tip plus one). Routes through the actor `ask`; on a stopped actor it
    /// returns [`CurveTreeHandleError::Unavailable`].
    #[allow(dead_code)] // dispatched by the merge path in commit 4; today: tests only.
    pub(crate) async fn ingest(
        &self,
        height: BlockHeight,
        txs: Vec<OwnedTxLeaves>,
    ) -> Result<(), CurveTreeHandleError> {
        self.actor
            .ask(IngestBlock { height, txs })
            .await
            .map_err(collapse_send_error)
    }

    /// Roll the client back to `fork_height` on a reorg.
    #[allow(dead_code)] // dispatched by the reorg path in commit 5; today: tests only.
    pub(crate) async fn rollback_to_fork(
        &self,
        fork_height: BlockHeight,
    ) -> Result<(), CurveTreeHandleError> {
        self.actor
            .ask(RollbackToFork { fork_height })
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
        assert!(handle.actor.is_alive(), "actor is alive after spawn");
    }
}
