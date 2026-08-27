// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ordered seal basis — the one snapshot a seal-bound assembly selects
//! against, and the read order that keeps the staleness guard sound.
//!
//! Carved out of [`start`](super::start) because the ordering is the whole
//! point of the code and deserves a file named for it: the pending block is
//! read to completion *before* the pscan seal, so a settlement can never pair
//! funding from before it with a generation from after it. Reading the two
//! concurrently is the regression this module exists to make unavailable —
//! see [`load_seal_basis`].

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_types::GlobalOutputIndex;
use tokio::sync::RwLock;

use super::dispatch::PendingPostStore;
use super::start::{
    load_pscan_state_for_engine, WalletFilePScanStoreError, WalletFilePendingSealStore,
    WalletFilePendingStoreError,
};
use crate::engine::{
    DaemonEngine, EconomicsEngine, Engine, EngineSignerKind, LedgerEngine, PendingTxEngine,
    RefreshEngine,
};

/// The ordered snapshot a seal-bound assembly selects against: the pending
/// block's reservation state **and** the pscan seal's funding records, read in
/// the one order that keeps the generation guard sound.
pub(crate) struct SealBasis {
    /// Reservation-release counter, carried to the seal (`seal_*`).
    generation: u64,
    /// Gindexes reserved by live records, the selection exclusion set.
    reserved: BTreeSet<GlobalOutputIndex>,
    /// The sealed pscan state, or `None` for a wallet that never scanned.
    pscan: Option<PScanState>,
}

impl SealBasis {
    /// The generation to carry to `seal_*`.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// The selection exclusion set.
    pub(crate) fn reserved(&self) -> &BTreeSet<GlobalOutputIndex> {
        &self.reserved
    }

    /// The pscan seal this basis was taken with.
    pub(crate) fn pscan(&self) -> Option<&PScanState> {
        self.pscan.as_ref()
    }

    /// Consume the basis for its pscan seal, where the caller needs it owned.
    pub(crate) fn into_pscan(self) -> Option<PScanState> {
        self.pscan
    }
}

/// Which of the two reads failed, so each seam can map it to its own typed
/// state refusal without inventing a shared error enum.
pub(crate) enum SealBasisError {
    /// The pending-block read failed.
    Pending(WalletFilePendingStoreError),
    /// The pscan-seal load failed.
    PScan(WalletFilePScanStoreError),
}

/// Take the [`SealBasis`] — **pending block first, pscan seal second**.
///
/// The order is the guarantee, not a style choice, which is why this is one
/// function rather than three call sites that happen to agree today.
///
/// Reading them concurrently (as all three seams did until review #572 round 6)
/// reopens the very race the generation counter closes. The pscan load can
/// return a funding set from *before* a settlement while the pending read
/// returns the generation from *after* it — pairing stale funding with a
/// current generation. The assembly then selects an input that the settled
/// record already spent, the seal's generation comparison matches, and the next
/// tick reads that input's absence as this record's own confirmation.
///
/// Pending-first makes every release fall on a decidable side:
///
/// - a release **before** the pending read is already reflected in the pscan
///   seal loaded afterwards, so the spent input is never selected;
/// - a release **after** the pending read moves the generation, so the carried
///   value no longer matches and the seal refuses as
///   [`SealAdmission::Stale`](shekyl_engine_state::pending_post_block::SealAdmission::Stale).
///
/// There is no third case, and the failure direction is a spurious retry rather
/// than an admitted stale seal — it fails closed.
///
/// **The premise the second bullet rests on**, stated because it is the part an
/// argument like this usually leaves implicit: a retirement is never visible in
/// the generation *before* the spend that caused it is visible in the pscan
/// seal. It holds by construction rather than by convention —
/// [`remove_settled`]'s evidence is the sweep's own accrual, and the accrual is
/// sealed inside the batch loop (`run_catchup_sweep`) before the end-of-sweep
/// dispatch tick that retires against it. So at tick time the sealed state and
/// the in-memory accrual are the same facts. Were the tick ever moved ahead of
/// that seal, a generation could move while the seal still advertised the spent
/// output as fundable, and this ordering would no longer be sufficient.
///
/// [`remove_settled`]: shekyl_engine_state::PendingPostBlock::remove_settled
///
/// [`SealBasis`]'s fields are private to this module and this is its only
/// constructor, so a seam cannot rebuild the pair by hand and reintroduce the
/// concurrent read. That is deliberate: the source pin over the seams can only
/// prove this function is *called*, never that a hand-rolled equivalent is
/// correctly ordered — so the type refuses the hand-rolled one instead.
#[allow(clippy::type_complexity)] // same engine-arc shape as load_pscan_state_for_engine
pub(crate) async fn load_seal_basis<S, D, L, E, R, P>(
    engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
    store: &PendingPostStore<WalletFilePendingSealStore<S, D, L, E, R, P>>,
) -> Result<SealBasis, SealBasisError>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync,
{
    // 1. Pending block, to completion. Generation and reservation set come from
    //    ONE locked read: the counter is only meaningful paired with the set it
    //    describes.
    let (generation, reserved) = store
        .read(|block| (block.generation(), block.reserved_gindexes()))
        .await
        .map_err(SealBasisError::Pending)?;
    // 2. Only now the pscan seal. Anything that settles from here on bumps the
    //    generation read above, so this funding set can only be newer than the
    //    basis the seal will check — never older.
    let pscan = load_pscan_state_for_engine(engine)
        .await
        .map_err(SealBasisError::PScan)?;
    Ok(SealBasis {
        generation,
        reserved,
        pscan,
    })
}
