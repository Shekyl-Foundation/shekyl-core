// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pending-post block's store: the sealed sink ([`PendingSealStore`])
//! and the one locked write path every writer shares
//! ([`PendingPostStore`]). Carved out of `pscan/dispatch.rs`, whose driver
//! is one of its writers, so the dispatch workflow file stays under its
//! decomposition ceiling (`scripts/ci/engine_decomposition_ratchet.conf`).

use std::sync::Arc;

use shekyl_engine_file::Durability;
use shekyl_engine_state::PendingPostBlock;

use crate::engine::error::PersistenceError;
use crate::engine::pending_post_gate::{Coverage, PendingPostGate};

/// The durable sink for the pending-post block — the `.wallet.pending` seal,
/// behind a trait so the driver is testable with an in-memory store and the
/// engine layer supplies the `WalletFile`-backed impl (same seam shape as
/// [`PScanStore`](super::task::PScanStore)).
///
/// The production impl MUST delegate to `WalletFile::save_pending_posts` /
/// `open_pending_posts` — the single write path / single payload kind the
/// §5 gate-11 enforcement pins. No other implementation may write
/// `.wallet.pending`.
pub(crate) trait PendingSealStore: Send + Sync + 'static {
    /// The store's failure type (boxed into
    /// [`DispatchError::Store`](super::dispatch::DispatchError::Store)).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the sealed block, or `None` for a wallet that has never
    /// assembled a bond post (the store then starts from
    /// [`PendingPostBlock::empty`]). A v1 seal under the v2 binary fails
    /// closed inside the impl's decode (`from_postcard_bytes` refuses the
    /// version) — pre-genesis, the operator re-assembles (rule 15).
    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PendingPostBlock>, Self::Error>> + Send;

    /// Seal the whole block (one postcard blob → one AEAD envelope → one
    /// atomic write; the R2-2 structural crash-atomicity). Returns the
    /// write's [`shekyl_engine_file::Durability`]. A broadcast requires
    /// [`shekyl_engine_file::Durability::Confirmed`].
    fn save(
        &self,
        block: &PendingPostBlock,
    ) -> impl std::future::Future<Output = Result<shekyl_engine_file::Durability, Self::Error>> + Send;

    /// The save's own cause, when `error` is a failed save of the file: a
    /// staking call answers it by cause, as a send does (Rick, 2026-11-19).
    /// Any other failure (encoding the block) is returned as it was.
    fn save_cause(error: Self::Error) -> Result<PersistenceError, Self::Error>;
}

/// The witness that the pending seal was covered by a save confirmed in this
/// process when its records were read ([`Coverage`]). Only the store mints
/// it, under its lock, and a record read back from the seal is sent only
/// with it ([`PBoundBytes::from_pending`](crate::engine::bond_assembly::PBoundBytes::from_pending)).
#[derive(Debug)]
pub(crate) struct Covered(());

impl Covered {
    /// A witness for a unit test that builds a loaded record by hand. Never
    /// a production mint.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self(())
    }
}

/// Why taking a seal for a broadcast failed ([`PendingPostStore::seal_reporting`]).
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError<E: std::error::Error + 'static> {
    /// The seal's save failed, for this cause: nothing was written and
    /// nothing sent. The caller answers it by cause (Rick, 2026-11-19).
    #[error("the seal was not saved: {0}")]
    NotSaved(#[source] PersistenceError),
    /// Reading the store failed, or the block could not be encoded.
    #[error(transparent)]
    Store(E),
}

/// What the open's one save of the seal did ([`PendingPostStore::cover_at_open`]).
#[derive(Debug)]
pub(crate) enum OpenCover<E> {
    /// No seal on disk: nothing was loaded, so nothing is covered or sent
    /// until a seal's own save.
    Empty,
    /// The loaded seal was saved; only [`Durability::Confirmed`] covers it.
    Saved(Durability),
    /// The save failed: the seal stays uncovered and its records unsent.
    NotSaved(E),
}

/// The single shared write path over the pending seal (§3.3 writer
/// discipline): an async mutex around load→modify→seal. Both writers — the
/// WI-2 assemble path (append) and this driver (transition/remove) — go
/// through this handle; the lock is what makes their two cadences safe
/// against read-modify-seal races. (Same shape as `PScanStore`, plus the
/// lock, because unlike the pscan seal this one legitimately has two
/// writers.)
///
/// **The lock is per-wallet, not per-instance.** It is injected as the
/// engine-owned [`PendingPostGate`] (`pending_gate`), so the driver's
/// store and the future WI-2 assemble path — which construct *independent*
/// stateless [`PendingSealStore`] adapters over the same `.wallet.pending`
/// file — still serialize against **one** mutex. Creating the lock inside
/// `new` would give each writer its own, which is precisely the lost-update
/// this discipline exists to forbid (assemble's append and the driver's
/// transition both load, then the last save wins). Requiring the caller to
/// pass the engine-held gate makes "one mutex per wallet" a construction
/// invariant, not a convention.
pub(crate) struct PendingPostStore<S> {
    seal: S,
    gate: Arc<PendingPostGate>,
}

impl<S: PendingSealStore> PendingPostStore<S> {
    /// Wrap the sealed-block store in the locked write path, sharing the
    /// engine-held gate (see the type docs: one mutex per wallet).
    pub(crate) fn new(seal: S, gate: Arc<PendingPostGate>) -> Self {
        Self { seal, gate }
    }

    /// Read the current block under the lock (a serialized snapshot; no
    /// seal write). The WI-2 assemble path reads the derived reservation
    /// set ([`PendingPostBlock::reserved_gindexes`]) through this.
    pub(crate) async fn read<R>(
        &self,
        f: impl FnOnce(&PendingPostBlock) -> R,
    ) -> Result<R, S::Error> {
        let _coverage = self.gate.lock().await;
        let block = self
            .seal
            .load()
            .await?
            .unwrap_or_else(PendingPostBlock::empty);
        Ok(f(&block))
    }

    /// One locked load→modify→seal cycle. The closure returns
    /// `(changed, R)`; the seal is rewritten only when `changed` is `true`
    /// (an unchanged tick must not burn an AEAD seal + fsync). The seal
    /// happens **inside** the closure's critical section — a caller that
    /// needs seal-before-send (§3.3) gets it by construction: `mutate`
    /// returns only after the transition is durable.
    pub(crate) async fn mutate<R>(
        &self,
        f: impl FnOnce(&mut PendingPostBlock) -> (bool, R),
    ) -> Result<R, S::Error> {
        let (out, durability) = self.mutate_reporting(f).await?;
        // A non-broadcast edit treats an applied write as success.
        crate::engine::dispatch_durability::accept_applied(&durability);
        Ok(out)
    }

    /// [`Self::mutate`], and the durability of the save it performed.
    ///
    /// An unchanged block reports [`shekyl_engine_file::Durability::Confirmed`]:
    /// nothing new was written. A broadcast caller refuses
    /// [`shekyl_engine_file::Durability::Unconfirmed`].
    pub(crate) async fn mutate_reporting<R>(
        &self,
        f: impl FnOnce(&mut PendingPostBlock) -> (bool, R),
    ) -> Result<(R, shekyl_engine_file::Durability), S::Error> {
        let mut coverage = self.gate.lock().await;
        let mut block = self
            .seal
            .load()
            .await?
            .unwrap_or_else(PendingPostBlock::empty);
        let (changed, out) = f(&mut block);
        let durability = if changed {
            self.save(&mut coverage, &block).await?
        } else {
            shekyl_engine_file::Durability::Confirmed
        };
        Ok((out, durability))
    }

    /// One locked cycle for the dispatch driver, which sends records read
    /// back from the seal. `f` is told the seal's [`Coverage`] as the cycle
    /// starts, and returns `(changed, R)` as [`Self::mutate`]'s closure does.
    /// The [`Covered`] witness comes back only when the seal is covered once
    /// the cycle's own save, if any, is done: a record read back in this
    /// cycle is sent only with it.
    pub(crate) async fn mutate_covering<R>(
        &self,
        f: impl FnOnce(&mut PendingPostBlock, Coverage) -> (bool, R),
    ) -> Result<(R, Option<Covered>), S::Error> {
        let mut coverage = self.gate.lock().await;
        let mut block = self
            .seal
            .load()
            .await?
            .unwrap_or_else(PendingPostBlock::empty);
        let (changed, out) = f(&mut block, *coverage);
        if changed {
            let durability = self.save(&mut coverage, &block).await?;
            crate::engine::dispatch_durability::accept_applied(&durability);
        }
        let covered = (*coverage == Coverage::Covered).then_some(Covered(()));
        Ok((out, covered))
    }

    /// The open's one save of the seal, before any driver sends (Rick,
    /// 2026-11-19): what the process loaded is covered only when this save
    /// is confirmed. Under the lock, so no writer's seal interleaves.
    ///
    /// `Err` is the load: a seal that cannot be read or decoded. A save
    /// that fails or is not confirmed is the [`OpenCover`] answer, not an
    /// error: the seal stays uncovered, its records stay unsent, and the
    /// next confirmed save of the file covers them.
    pub(crate) async fn cover_at_open(&self) -> Result<OpenCover<S::Error>, S::Error> {
        let mut coverage = self.gate.lock().await;
        let Some(block) = self.seal.load().await? else {
            return Ok(OpenCover::Empty);
        };
        Ok(match self.save(&mut coverage, &block).await {
            Ok(durability) => OpenCover::Saved(durability),
            Err(error) => OpenCover::NotSaved(error),
        })
    }

    /// Every save of the seal: a confirmed one covers the whole file, an
    /// unconfirmed one uncovers it, and a failed one wrote nothing, so the
    /// coverage stands.
    async fn save(
        &self,
        coverage: &mut Coverage,
        block: &PendingPostBlock,
    ) -> Result<Durability, S::Error> {
        let durability = self.seal.save(block).await?;
        *coverage = match durability {
            Durability::Confirmed => Coverage::Covered,
            Durability::Unconfirmed(_) => Coverage::Uncovered,
        };
        Ok(durability)
    }

    /// Take a seal for a broadcast: [`Self::mutate_reporting`], except that
    /// a save whose durability is not confirmed is undone under the same
    /// guard. `seal` edits the block as `mutate_reporting`'s closure does;
    /// `unseal` takes that seal back out and says whether it was there. An unconfirmed seal sends nothing,
    /// so it is removed and its lane reopens, and the caller answers with
    /// the save's own cause (Rick, 2026-11-19). Under one guard, no other
    /// writer, the dispatch driver's tick included, ever reads the seal in
    /// between: the driver sends a `Pending` bond post it selects.
    ///
    /// The removal is itself a save. One that fails, or whose own
    /// durability is not confirmed, is logged, never the answer: the seal
    /// stays on disk, or a power loss can bring it back (`docs/FOLLOWUPS.md`,
    /// the dispatch-driver row). Either way the seal is uncovered, so the
    /// dispatch driver does not send it ([`Self::mutate_covering`]).
    ///
    /// A seal whose save fails is [`SealError::NotSaved`], with the save's
    /// cause; a load that fails is [`SealError::Store`].
    pub(crate) async fn seal_reporting<R>(
        &self,
        seal: impl FnOnce(&mut PendingPostBlock) -> (bool, R),
        unseal: impl FnOnce(&mut PendingPostBlock) -> bool,
    ) -> Result<(R, shekyl_engine_file::Durability), SealError<S::Error>> {
        let mut coverage = self.gate.lock().await;
        let mut block = self
            .seal
            .load()
            .await
            .map_err(SealError::Store)?
            .unwrap_or_else(PendingPostBlock::empty);
        let (changed, out) = seal(&mut block);
        if !changed {
            return Ok((out, shekyl_engine_file::Durability::Confirmed));
        }
        let durability =
            self.save(&mut coverage, &block)
                .await
                .map_err(|error| match S::save_cause(error) {
                    Ok(cause) => SealError::NotSaved(cause),
                    Err(other) => SealError::Store(other),
                })?;
        if let shekyl_engine_file::Durability::Unconfirmed(why) = &durability {
            let unsealed = unseal(&mut block);
            debug_assert!(
                unsealed,
                "the seal just saved is in the block it was saved in"
            );
            match self.save(&mut coverage, &block).await {
                Ok(shekyl_engine_file::Durability::Confirmed) => {}
                Ok(shekyl_engine_file::Durability::Unconfirmed(again)) => tracing::warn!(
                    %why,
                    %again,
                    "an unconfirmed seal sent nothing and was removed, but the removal is \
                     unconfirmed too; a power loss can bring the seal back"
                ),
                Err(error) => tracing::error!(
                    %why,
                    %error,
                    "an unconfirmed seal sent nothing, but removing it failed; it stays on disk"
                ),
            }
        }
        Ok((out, durability))
    }
}
