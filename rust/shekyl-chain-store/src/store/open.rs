// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a path becomes a [`ChainStore`](super::ChainStore).
//!
//! Fresh-vs-existing is one syscall: `create_new` either claims the path
//! or fails with `AlreadyExists`. An existing file is screened on a
//! read-only open, then claimed with a writable one. redb opens read-only
//! only by path, so the two opens cannot share a descriptor. The writable
//! open records the engine's allocator state when it closes, which is why
//! a refusal has to happen on the read-only open: a refusal of that open
//! writes nothing to the inode it judged. A directory entry replaced
//! between the two opens is a different file, and dropping the refused
//! writable open writes the inode that open took. The creation lock is
//! held from before `create_new` until the engine holds the file
//! ([`crate::creation::PathGuard`]).
//!
//! [`ReleaseAdmission`] says whether that read-only screen also admits
//! the file against a release pin table. The unanchored doors do not read
//! the chain body. [`ChainStore::with_release`](super::ChainStore::with_release)
//! does, on this screen and again on the handle the writable open returns,
//! because the file can change between the two opens.

use std::path::Path;

use redb::{Database, ReadableDatabase};
use shekyl_chain_rules::{AtHeight, ReleaseAnchors, Tip};
use shekyl_types::BlockHeight;

use super::chain_reads::{self, ReadFault};
use super::{header, ChainStore, EngineError, Horizons, StoreCannot, StoreError, CACHE_SIZE};
use crate::apply_policy::ApplyPolicy;
use crate::codec::SettlementEpochBlocks;
use crate::creation::CutShort;
use crate::provenance::Provenance;

/// Whether this open admits the chain against a release pin table.
///
/// [`Unanchored`](Self::Unanchored) verifies the header and does not read
/// the body. [`Anchored`](Self::Anchored) admits `anchors` on that same
/// read. [`ReleaseAnchors::EMPTY`] is a table with no pins, not a skipped
/// admission: the walk still runs, and a tip the snapshot cannot read is
/// a fault.
#[derive(Clone, Copy)]
pub(super) enum ReleaseAdmission<'a> {
    /// [`ChainStore::with_horizons`](super::ChainStore::with_horizons) and
    /// the doors that call it.
    Unanchored,
    /// [`ChainStore::with_release`](super::ChainStore::with_release).
    Anchored(&'a ReleaseAnchors),
}

/// CEN-E5 over one read transaction.
///
/// `Ok` agrees, including an empty chain and an empty table. A
/// contradiction is [`StoreCannot::ReleasePin`]. A read that cannot
/// answer is that read's error.
///
/// # Errors
///
/// [`StoreCannot::ReleasePin`] when a pin at or below the tip is not the
/// block recorded there. A fault from the tip or the block read passes
/// through: a fault is not agreement and not a pin mismatch.
pub(super) fn admit_pins(
    txn: &redb::ReadTransaction,
    anchors: &ReleaseAnchors,
) -> Result<(), StoreError> {
    let tip = chain_reads::tip_of(txn).map_err(ReadFault::into_plain)?;
    let recorded = tip.as_ref().map(|(height, info)| Tip {
        height: BlockHeight::from_raw(*height),
        hash: info.hash,
    });
    match anchors.conflict_over(recorded, |height| -> Result<_, StoreError> {
        let at = chain_reads::info_at(txn, tip.as_ref(), height.to_raw())
            .map_err(ReadFault::into_plain)?;
        Ok(match at {
            AtHeight::Recorded(info) => Some(info.hash),
            AtHeight::AboveTip => None,
        })
    })? {
        None => Ok(()),
        Some(conflict) => Err(StoreCannot::ReleasePin(conflict).into()),
    }
}

/// Create or open `path`, and report a creation this open finished.
///
/// # Errors
///
/// [`StoreCannot::EmptyApplyStub`] if the policy stubs no families —
/// checked before the path is touched. The header refusals of
/// [`filter_readable`], the engine's open errors, and, when `admission`
/// is [`ReleaseAdmission::Anchored`], the pin refusals of [`admit_pins`].
pub(super) fn open_at(
    path: &Path,
    apply_policy: ApplyPolicy,
    horizons: Horizons,
    admission: ReleaseAdmission<'_>,
) -> Result<(ChainStore, Option<CutShort>), StoreError> {
    let epoch = horizons.epoch();
    apply_policy
        .reject_empty_stub()
        .map_err(|crate::apply_policy::EmptyApplyStub| StoreCannot::EmptyApplyStub)?;
    let guard = crate::creation::PathGuard::acquire(path)
        .map_err(|error| EngineError::Open(redb::DatabaseError::Storage(error.into())))?;
    let mut builder = redb::Builder::new();
    builder.set_cache_size(CACHE_SIZE);
    let (db, provenance, cut) = match create_fresh(&builder, path, apply_policy, epoch)? {
        Some((db, provenance)) => (db, provenance, None),
        None => open_existing(&builder, path, apply_policy, epoch, admission, &guard)?,
    };
    Ok((
        ChainStore::opened(db, apply_policy, horizons, provenance),
        cut,
    ))
}

/// Reopen an existing file.
///
/// The read-only open is the refusal filter. [`filter_readable`] rejects
/// a file with nothing written. `RepairAborted` is not a refusal: a
/// read-only open returns it before any table read when the file needs
/// recovery, and only the writable open repairs it. That open writes the
/// repaired header before it returns the handle, so the repair is in
/// place — this is the power-loss restart. Pin admission for that file
/// is the one on the handle [`open_at`] returns — the body cannot be
/// read until the repair has run. A refusal after the repair leaves the
/// recorded blocks in the file. The writable open's [`judge`]
/// is the provenance of the handle, not the filter's. A creation a power
/// loss cut short is finished ([`crate::creation`]). A file with no table
/// is sealed in place under the writable open, which holds the engine's
/// exclusive lock, and reported as [`CutShort::Unsealed`]. A file the
/// engine would not open is moved aside only when
/// [`creation::open_is_foreign`](crate::creation::open_is_foreign) and the
/// file is an initialization the engine never finished. Any other such
/// file is refused with the engine's own error. `guard` is held by
/// [`open_at`] for the whole decision.
fn open_existing(
    builder: &redb::Builder,
    path: &Path,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
    admission: ReleaseAdmission<'_>,
    guard: &crate::creation::PathGuard,
) -> Result<(Database, Provenance, Option<CutShort>), StoreError> {
    match builder.open_read_only(path) {
        Ok(read_only) => filter_readable(&read_only, epoch, admission)?,
        Err(redb::DatabaseError::RepairAborted) => {}
        Err(refused) if crate::creation::open_is_foreign(&refused) => {
            return finish_uninitialized(builder, path, policy, epoch, guard, refused);
        }
        Err(refused) => return Err(EngineError::Open(refused).into()),
    }
    let db = builder.open(path).map_err(EngineError::Open)?;
    // `create_file` commits an empty database before the seal's
    // transaction commits, so a power loss between the two leaves a valid
    // file with no table at all (PB-S2's first replay). Nothing in it can
    // be lost: it is sealed here, as `create_sealed` would have.
    let (provenance, cut) = match judge(&db, epoch)? {
        Some(provenance) => (provenance, None),
        None => (seal_new(&db, policy, epoch)?, Some(CutShort::Unsealed)),
    };
    Ok((db, provenance, cut))
}

/// One read of a database the read-only open returned.
///
/// A file with no table has no block for a pin to contradict. A sealed
/// file is verified, and an anchored open admits its pins before this
/// read ends, so the database can be dropped — releasing the shared lock
/// — before the writable open.
fn filter_readable(
    db: &impl ReadableDatabase,
    epoch: SettlementEpochBlocks,
    admission: ReleaseAdmission<'_>,
) -> Result<(), StoreError> {
    let txn = db.begin_read().map_err(EngineError::BeginRead)?;
    if verified_header(&txn, epoch)?.is_none() {
        return Ok(());
    }
    if let ReleaseAdmission::Anchored(anchors) = admission {
        admit_pins(&txn, anchors)?;
    }
    Ok(())
}

/// What an existing file is to this store: its verified provenance, or
/// `None` for a file with no table at all, a creation stopped before its
/// seal ([`crate::creation`]). A file with any table and no seal, or
/// another layout or schedule, is [`header::verify`]'s refusal.
fn judge(
    db: &impl ReadableDatabase,
    epoch: SettlementEpochBlocks,
) -> Result<Option<Provenance>, StoreError> {
    let txn = db.begin_read().map_err(EngineError::BeginRead)?;
    verified_header(&txn, epoch)
}

/// `Ok(None)` is a file with no table. `Ok(Some)` is a header this binary
/// vouches for.
fn verified_header(
    txn: &redb::ReadTransaction,
    epoch: SettlementEpochBlocks,
) -> Result<Option<Provenance>, StoreError> {
    if crate::creation::no_table(txn)? {
        return Ok(None);
    }
    header::verify(txn, epoch).map(Some)
}

/// Claim `path` with `create_new` and create a sealed store in it. `None`
/// when the path already exists. A file this made and the engine or the
/// seal then refused is removed again, so a failed create does not leave a
/// headerless file the next open refuses.
fn create_fresh(
    builder: &redb::Builder,
    path: &Path,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
) -> Result<Option<(Database, Provenance)>, StoreError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(e) => return Err(EngineError::Open(redb::DatabaseError::Storage(e.into())).into()),
    };
    match create_sealed(builder, file, policy, epoch) {
        Ok(fresh) => Ok(Some(fresh)),
        Err(e) => {
            // The path exists only because `create_new` just made it.
            // `create_sealed` has dropped its `Database`, so the file is
            // unlocked.
            drop(std::fs::remove_file(path));
            Err(e)
        }
    }
}

/// The engine refused `path` as not a database. Move it aside when it is
/// an unfinished initialization and seal a fresh store in the file the
/// move claimed. The aside stays if the seal fails: it is the operator's
/// file, and the replacement is the one this process just created.
fn finish_uninitialized(
    builder: &redb::Builder,
    path: &Path,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
    guard: &crate::creation::PathGuard,
    refused: redb::DatabaseError,
) -> Result<(Database, Provenance, Option<CutShort>), StoreError> {
    debug_assert_eq!(guard.store(), path);
    let Some(replaced) = crate::creation::set_aside_unfinished_init(guard)
        .map_err(|error| EngineError::Open(redb::DatabaseError::Storage(error.into())))?
    else {
        return Err(EngineError::Open(refused).into());
    };
    match create_sealed(builder, replaced.file, policy, epoch) {
        Ok((db, provenance)) => Ok((
            db,
            provenance,
            Some(CutShort::Uninitialized { to: replaced.to }),
        )),
        Err(error) => {
            drop(std::fs::remove_file(path));
            Err(error)
        }
    }
}

/// Hand a just-created, still-empty file to the engine and seal its header
/// in the first transaction, under the same durability every batch
/// commits with.
///
/// Everything that can fail between `create_new` and a usable store runs
/// here, so the caller has exactly one place to undo the creation. On
/// `Err` the `Database` is dropped before returning, releasing the
/// engine's file lock so the caller's `remove_file` can succeed.
fn create_sealed(
    builder: &redb::Builder,
    file: std::fs::File,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
) -> Result<(Database, Provenance), StoreError> {
    let db = builder.create_file(file).map_err(EngineError::Open)?;
    let provenance = seal_new(&db, policy, epoch)?;
    Ok((db, provenance))
}

/// Seal a database that has no table yet: the header, in one transaction,
/// under the durability every batch commits with.
fn seal_new(
    db: &Database,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
) -> Result<Provenance, StoreError> {
    let txn = super::arm_write(db)?;
    let provenance = header::seal(&txn, policy, epoch)?;
    txn.commit().map_err(EngineError::Commit)?;
    Ok(provenance)
}
