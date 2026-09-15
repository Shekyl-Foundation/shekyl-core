// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store header: two `properties` cells the store owns outright — and
//! the typed cell access every other `properties` read or write goes
//! through.
//!
//! - `schema_version` ([`SchemaVersionCell`]) — sealed into a fresh file's
//!   **first** transaction and checked before any other read or write on
//!   reopen (§11.1(a)). Reaching an open-or-create table path first would
//!   stamp a stale file to the current version in passing and the mismatch
//!   could never fire, which is why [`verify`] runs in a read transaction
//!   with no write side effects.
//! - `apply_policy` ([`ApplyPolicyCell`]) — the file's
//!   [`Provenance`]: sealed with the creating session's stubbed set and
//!   [widened](widen) inside every stubbed batch's own transaction, so the
//!   taint commits with the rows it describes or not at all.
//!
//! No public write path reaches either cell. [`seal`] and [`widen`] are
//! their only writers; [`upsert`] is `pub(super)` and its public caller,
//! `WriteBatch::upsert_property`, is bounded to chain-state cells.

use redb::{ReadTransaction, ReadableTable, WriteTransaction};

use crate::apply_policy::ApplyPolicy;
use crate::codec::{ApplyPolicyCell, Canonical, PropertyCell, SchemaVersionCell, SCHEMA_VERSION};
use crate::provenance::Provenance;
use crate::schema::PROPERTIES;

use super::error::{CellFault, EngineError, StoreCannot, StoreError, StoreInvariant};

/// Write both header cells into a fresh store.
///
/// The provenance a fresh file starts with is the creating session's own
/// stubbed set: a store *created* under a stubbed policy has been written
/// under it from its first byte.
pub(super) fn seal(txn: &WriteTransaction, policy: ApplyPolicy) -> Result<Provenance, StoreError> {
    let provenance = Provenance::FULL.widened_by(policy);
    upsert::<SchemaVersionCell>(txn, &SCHEMA_VERSION)?;
    upsert::<ApplyPolicyCell>(txn, &provenance.stubbed())?;
    Ok(provenance)
}

/// Check an existing store's layout version and read its provenance.
///
/// # Errors
///
/// [`StoreCannot::SchemaVersionAbsent`] if there is no `properties` table
/// or no `schema_version` cell; [`StoreCannot::SchemaVersionMismatch`] if
/// the version is not [`SCHEMA_VERSION`]; [`StoreInvariant::CellCorrupt`] if
/// a header cell is present but malformed, or `apply_policy` is missing.
pub(super) fn verify(txn: &ReadTransaction) -> Result<Provenance, StoreError> {
    let table = match txn.open_table(PROPERTIES) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(StoreCannot::SchemaVersionAbsent.into())
        }
        Err(e) => return Err(EngineError::Table(e).into()),
    };
    let found = get::<SchemaVersionCell>(&table)?.ok_or(StoreCannot::SchemaVersionAbsent)?;
    if found != SCHEMA_VERSION {
        return Err(StoreCannot::SchemaVersionMismatch {
            found,
            expected: SCHEMA_VERSION,
        }
        .into());
    }
    let stubbed = get::<ApplyPolicyCell>(&table)?.ok_or(absent::<ApplyPolicyCell>())?;
    Ok(Provenance::of(stubbed))
}

/// Widen the provenance cell by `policy`'s stubbed set, in `txn`.
///
/// Read-modify-write inside the batch's own transaction: the union is
/// over what the file *currently* records, and it commits when the batch
/// does. A `Full` policy is a no-op that still reads the cell.
pub(super) fn widen(txn: &WriteTransaction, policy: ApplyPolicy) -> Result<Provenance, StoreError> {
    let current = {
        let table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
        get::<ApplyPolicyCell>(&table)?.ok_or(absent::<ApplyPolicyCell>())?
    };
    let after = Provenance::of(current).widened_by(policy);
    if after.stubbed() != current {
        upsert::<ApplyPolicyCell>(txn, &after.stubbed())?;
    }
    Ok(after)
}

/// Read cell `C` from an open `properties` table.
///
/// `Ok(None)` if absent; [`StoreInvariant::CellCorrupt`] if present but not an
/// encoding of `C::Value`.
pub(super) fn get<C: PropertyCell>(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<C::Value>, StoreError> {
    let Some(guard) = table.get(C::KEY).map_err(EngineError::Storage)? else {
        return Ok(None);
    };
    C::Value::decode(guard.value()).map(Some).map_err(|cause| {
        StoreInvariant::CellCorrupt {
            key: C::KEY,
            fault: CellFault::Undecodable(cause),
        }
        .into()
    })
}

/// Upsert cell `C` in `txn` — a header cell is a register, overwritten by
/// design, and the verb declares it (C2-R8 §7.3). Opens (creating if
/// needed) the `properties` table for the duration of the write.
pub(super) fn upsert<C: PropertyCell>(
    txn: &WriteTransaction,
    value: &C::Value,
) -> Result<(), StoreError> {
    let mut table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
    table
        .insert(C::KEY, value.encode().as_slice())
        .map(drop)
        .map_err(|e| EngineError::Storage(e).into())
}

fn absent<C: PropertyCell>() -> StoreError {
    StoreInvariant::CellCorrupt {
        key: C::KEY,
        fault: CellFault::Absent,
    }
    .into()
}
