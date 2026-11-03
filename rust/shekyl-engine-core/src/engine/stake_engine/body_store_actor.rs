// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona body store's owning actor (`CURVE_TREE_CLIENT.md` §11.1).
//!
//! `P`'s `.pstore` is one redb file, locked for as long as its
//! [`BodyStore`] lives, and the store holds the key its chunks are sealed
//! under. This actor is the store's one owner: it opens shards, hands out
//! their chunks as owned plaintext copies, and erases rows, each by message.
//! Nothing else holds the store, so the key never leaves it
//! (`WALLET_SIDE_STORE.md` `WSS-Q13`), and it drops the store in `on_stop`,
//! so an awaited [`BodyStoreHandle::shutdown`] means the file is closed.
//!
//! A separate actor from the stake engine's, on purpose: the serving loop
//! asks for one storage chunk per reply, about 52 replies per shard, and
//! those must not queue in front of bond signing (one mechanism, one job;
//! `05-system-thinking.mdc`).

use std::ops::ControlFlow;

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError};
use kameo::message::{Context, Message};
use shekyl_p_host::{HeldShardSource, ProviderError};
use shekyl_p_store::{BodyStore, HeldShard, StoreError};
use shekyl_types::ShardId;

/// The owning actor. The store is an `Option` only so `on_stop` can take it.
pub(crate) struct BodyStoreActor {
    store: Option<BodyStore>,
}

impl BodyStoreActor {
    fn store(&self) -> &BodyStore {
        self.store
            .as_ref()
            .expect("kameo runs no handler after on_stop, which alone takes the store")
    }
}

impl Actor for BodyStoreActor {
    type Args = BodyStore;
    type Error = Infallible;

    async fn on_start(store: BodyStore, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self { store: Some(store) })
    }

    /// Fail-stop on panic, the kameo default, locked at the type layer.
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Drop the store here, not with the actor value: kameo sets the shutdown
    /// result only after `on_stop` returns, so this is what makes
    /// [`BodyStoreHandle::shutdown`]'s await mean the file is closed and the
    /// store key wiped (`StoreKey` is `ZeroizeOnDrop`).
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        drop(self.store.take());
        Ok(())
    }
}

/// Open a held shard for serving.
pub(crate) struct OpenHeldShard {
    pub shard_id: ShardId,
}

impl Message<OpenHeldShard> for BodyStoreActor {
    type Reply = Result<Option<HeldShard>, StoreError>;

    async fn handle(
        &mut self,
        msg: OpenHeldShard,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.store().open_shard(msg.shard_id)
    }
}

/// One storage chunk of an opened shard, as an owned plaintext copy.
pub(crate) struct ReadHeldChunk {
    pub held: HeldShard,
    pub index: u32,
}

impl Message<ReadHeldChunk> for BodyStoreActor {
    type Reply = Result<Vec<u8>, StoreError>;

    async fn handle(
        &mut self,
        msg: ReadHeldChunk,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.store().read_chunk(&msg.held, msg.index)
    }
}

/// Erase rows the pin-release gate has cleared (`WSS-Q8`).
pub(crate) struct EraseShards {
    pub shard_ids: Vec<u64>,
}

impl Message<EraseShards> for BodyStoreActor {
    type Reply = Result<(), StoreError>;

    async fn handle(
        &mut self,
        msg: EraseShards,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        for id in msg.shard_ids {
            self.store().erase_shard(ShardId::from_raw(id))?;
        }
        Ok(())
    }
}

/// Write a shard's frame. No production caller yet: fill (`WSS-Q4`) is not
/// built; tests fill through this so they reach the store the way the
/// serving path does.
#[cfg(test)]
pub(crate) struct PutShard {
    pub shard_id: ShardId,
    pub frame: Vec<u8>,
}

#[cfg(test)]
impl Message<PutShard> for BodyStoreActor {
    type Reply = Result<(), StoreError>;

    async fn handle(
        &mut self,
        msg: PutShard,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.store().put_shard(msg.shard_id, &msg.frame)
    }
}

/// `Clone` handle on the body-store actor: a mailbox address, not a share of
/// the store. The stake engine's handle carries one and erases through it;
/// the serving path gets [`Self::reads`], which does not keep the actor
/// alive.
#[derive(Clone)]
pub(crate) struct BodyStoreHandle {
    actor: ActorRef<BodyStoreActor>,
}

impl BodyStoreHandle {
    /// Spawn the owner over an opened store.
    pub(crate) fn spawn(store: BodyStore) -> Self {
        Self {
            actor: BodyStoreActor::spawn(store),
        }
    }

    /// Erase `shard_ids` (`WSS-Q8`). A missing row is success.
    ///
    /// # Errors
    ///
    /// A store fault, or an owner that has stopped, as a diagnostic.
    pub(crate) async fn erase(&self, shard_ids: Vec<u64>) -> Result<(), String> {
        self.actor
            .ask(EraseShards { shard_ids })
            .await
            .map_err(|e| format!("persona body store erase failed: {e:?}"))
    }

    /// The non-owning form, for a weak stake-engine handle.
    pub(crate) fn downgrade(&self) -> WeakBodyStoreHandle {
        WeakBodyStoreHandle {
            actor: self.actor.downgrade(),
        }
    }

    /// The serving path's reads: open and read-chunk, by message, through a
    /// weak reference that never keeps the owner alive.
    pub(crate) fn reads(&self) -> BodyReads {
        BodyReads {
            actor: self.actor.downgrade(),
        }
    }

    /// Stop the owner and wait until it has dropped the store. When this
    /// returns the `.pstore` file is closed.
    pub(crate) async fn shutdown(&self) {
        if let Err(not_running) = self.actor.stop_gracefully().await {
            tracing::debug!(?not_running, "persona body-store actor already stopping");
        }
        if let Err(hook) = self.actor.wait_for_shutdown_result().await {
            tracing::warn!(?hook, "the persona body-store actor's stop hook failed");
        }
    }

    /// Fill a shard, as a test would before serving it.
    #[cfg(test)]
    pub(crate) async fn put_for_test(&self, shard_id: ShardId, frame: &[u8]) {
        self.actor
            .ask(PutShard {
                shard_id,
                frame: frame.to_vec(),
            })
            .await
            .expect("put shard");
    }
}

/// A non-owning [`BodyStoreHandle`], for the stake engine's weak handle: it
/// reaches the owner while something else keeps it, and never keeps it
/// alive itself (the store holds a key; `StakeEngineHandle::downgrade`).
#[derive(Clone)]
pub(crate) struct WeakBodyStoreHandle {
    actor: WeakActorRef<BodyStoreActor>,
}

impl WeakBodyStoreHandle {
    /// A strong handle iff the owner is still running.
    pub(crate) fn upgrade(&self) -> Option<BodyStoreHandle> {
        let actor = self.actor.upgrade()?;
        actor.is_alive().then_some(BodyStoreHandle { actor })
    }
}

/// The serving path's view of the body store: reads by message to its owner.
///
/// Called on the endpoint's blocking pool: each read parks the calling
/// thread on the owner's reply (`blocking_send`), so it must never be called
/// from an async executor thread. An owner that has stopped is a store
/// fault, which the endpoint renders as its bare 503.
pub(crate) struct BodyReads {
    actor: WeakActorRef<BodyStoreActor>,
}

impl BodyReads {
    fn owner(&self) -> Result<ActorRef<BodyStoreActor>, ProviderError> {
        self.actor
            .upgrade()
            .filter(ActorRef::is_alive)
            .ok_or_else(|| ProviderError::other("persona body store is closed"))
    }
}

impl HeldShardSource for BodyReads {
    fn open_shard(&self, shard_id: ShardId) -> Result<Option<HeldShard>, ProviderError> {
        self.owner()?
            .ask(OpenHeldShard { shard_id })
            .blocking_send()
            .map_err(|e| ProviderError::other(format!("persona body store open failed: {e:?}")))
    }

    fn read_chunk(&self, held: &HeldShard, index: u32) -> Result<Vec<u8>, ProviderError> {
        self.owner()?
            .ask(ReadHeldChunk {
                held: held.clone(),
                index,
            })
            .blocking_send()
            .map_err(|e| ProviderError::other(format!("persona body store read failed: {e:?}")))
    }
}

#[cfg(test)]
#[path = "body_store_actor_tests.rs"]
mod tests;
