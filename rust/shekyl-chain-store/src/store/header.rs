// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store header: the `properties` cells the store owns outright — and
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
//! - `settlement_epoch_blocks` ([`SettlementEpochBlocksCell`]) — the
//!   schedule the file was built under (SCW-2): sealed from the creating
//!   session's value, compared at every open, refused on mismatch. Never
//!   widened or rewritten — a datadir has one schedule for its whole life.
//! - `rule_coverage_gaps` ([`CoverageGapsCell`]) and `passed_through_facts`
//!   ([`PassedThroughFactsCell`]) — the other two [`Provenance`] components
//!   (S-CHAIN-W §3.8, §3.2): sealed empty, [widened](widen_gaps) by
//!   `connect` inside its own batch, read back with `apply_policy` at
//!   every open and every commit.
//!
//! No public write path reaches any of them. [`seal`], [`widen`],
//! [`widen_gaps`] and [`widen_passed_through`] are their only writers;
//! [`put`] is `pub(super)` and its public caller,
//! `WriteBatch::upsert_property`, is bounded to chain-state cells.
//! Store-owned header writes are `put`, not `upsert`: they are not
//! choosing a keyed-table verb.

use redb::{ReadTransaction, ReadableTable, WriteTransaction};

use crate::apply_policy::ApplyPolicy;
use crate::codec::{
    ApplyPolicyCell, Blob, Canonical, CoverageGaps, CoverageGapsCell, CurveTreeState,
    PassedThroughFacts, PassedThroughFactsCell, PropertyCell, PropertyCellBytes, Raw,
    SchemaVersionCell, SettlementEpochBlocks, SettlementEpochBlocksCell, SCHEMA_VERSION,
};
use crate::provenance::Provenance;
use crate::schema::{self, PROPERTIES};

use super::error::{CellFault, EngineError, StoreCannot, StoreError, StoreInvariant};

/// Write the header cells into a fresh store.
///
/// The provenance a fresh file starts with is the creating session's own
/// stubbed set (and no gaps, no pass-through — nothing has been connected):
/// a store *created* under a stubbed policy has been written under it from
/// its first byte. The schedule pin is the session's value, and is never
/// written again.
pub(super) fn seal(
    txn: &WriteTransaction,
    policy: ApplyPolicy,
    epoch: SettlementEpochBlocks,
) -> Result<Provenance, StoreError> {
    let provenance = Provenance::FULL.widened_by(policy);
    put::<SchemaVersionCell>(txn, &SCHEMA_VERSION)?;
    put::<ApplyPolicyCell>(txn, &provenance.stubbed())?;
    put::<SettlementEpochBlocksCell>(txn, &epoch)?;
    put::<CoverageGapsCell>(txn, &CoverageGaps::NONE)?;
    put::<PassedThroughFactsCell>(txn, &PassedThroughFacts::NONE)?;
    // Amendment A2 (SCR-17): every table with a writer exists from the
    // first commit, so no reader ever has to read *absent table* as *empty
    // table*. The set is the catalogue's, filtered by value shape.
    for table in schema::UNDO_TARGETS {
        table.create(txn)?;
    }
    // S-CURVE (`SCU-Q1`, SCU-1): the empty tree is a **written** row, so a
    // reader never has to read *absent summary* as *empty tree* — the
    // absence-as-default the C++ meta cells had.
    txn.open_table(schema::CURVE_TREE_META)
        .map_err(EngineError::Table)?
        .insert((), CurveTreeState::EMPTY.encoded().as_encoded())
        .map_err(EngineError::Storage)?;
    Ok(provenance)
}

/// Amendment A2's other half: a sealed file has every table with a writer.
/// One that lacks a table this store's seal would have created was not
/// written by this store — SI-7, the table named as the cell.
fn verify_sealed_tables(txn: &ReadTransaction) -> Result<(), StoreError> {
    for table in schema::UNDO_TARGETS.iter().filter(|t| t.sealed()) {
        if !table.exists(txn)? {
            return Err(StoreInvariant::CellCorrupt {
                key: table.name(),
                fault: CellFault::Absent,
            }
            .into());
        }
    }
    Ok(())
}

/// Read the three provenance components from an open `properties` table.
/// Each is sealed at create, so absence is corruption, not "fresh".
fn provenance_of(
    table: &impl ReadableTable<&'static str, Blob<PropertyCellBytes>>,
) -> Result<Provenance, StoreError> {
    let stubbed = get::<ApplyPolicyCell>(table)?.ok_or(absent::<ApplyPolicyCell>())?;
    let gaps = get::<CoverageGapsCell>(table)?.ok_or(absent::<CoverageGapsCell>())?;
    let passed = get::<PassedThroughFactsCell>(table)?.ok_or(absent::<PassedThroughFactsCell>())?;
    Ok(Provenance::of_parts(stubbed, gaps, passed))
}

/// Check an existing store's layout version and schedule pin, and read its
/// provenance.
///
/// # Errors
///
/// [`StoreCannot::SchemaVersionAbsent`] if there is no `properties` table
/// or no `schema_version` cell; [`StoreCannot::SchemaVersionMismatch`] if
/// the version is not [`SCHEMA_VERSION`];
/// [`StoreCannot::SettlementEpochMismatch`] if the file was built under a
/// schedule other than `epoch`; [`StoreInvariant::CellCorrupt`] if a header
/// cell is present but malformed, or `apply_policy` /
/// `settlement_epoch_blocks` is missing.
pub(super) fn verify(
    txn: &ReadTransaction,
    epoch: SettlementEpochBlocks,
) -> Result<Provenance, StoreError> {
    let table = match txn.open_table(PROPERTIES) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(StoreCannot::SchemaVersionAbsent.into())
        }
        // The header table's stored type is not this layout's (§11.1(f)
        // moved it): a file from another layout, refused one step before
        // the version cell could say which.
        Err(redb::TableError::TableTypeMismatch { .. }) => {
            return Err(StoreCannot::LayoutForeign {
                expected: SCHEMA_VERSION,
            }
            .into())
        }
        Err(e) => return Err(EngineError::Table(e).into()),
    };
    // Version before table set: a file at another version is *foreign*,
    // not *corrupt*, and must be named as such even where its table set
    // would also fail the current seal's check.
    let found = get::<SchemaVersionCell>(&table)?.ok_or(StoreCannot::SchemaVersionAbsent)?;
    if found != SCHEMA_VERSION {
        return Err(StoreCannot::SchemaVersionMismatch {
            found,
            expected: SCHEMA_VERSION,
        }
        .into());
    }
    verify_sealed_tables(txn)?;
    let pinned =
        get::<SettlementEpochBlocksCell>(&table)?.ok_or(absent::<SettlementEpochBlocksCell>())?;
    if pinned != epoch {
        return Err(StoreCannot::SettlementEpochMismatch {
            pinned,
            session: epoch,
        }
        .into());
    }
    provenance_of(&table)
}

/// Widen the `apply_policy` cell by `policy`'s stubbed set, in `txn`, and
/// read back the whole provenance the file now records.
///
/// Read-modify-write inside the batch's own transaction: the union is
/// over what the file *currently* records — including any gaps or
/// pass-through the batch's own connects widened — and it commits when
/// the batch does. A `Full` policy is a no-op that still reads the cells.
pub(super) fn widen(txn: &WriteTransaction, policy: ApplyPolicy) -> Result<Provenance, StoreError> {
    let current = {
        let table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
        provenance_of(&table)?
    };
    let after = current.widened_by(policy);
    if after.stubbed() != current.stubbed() {
        put::<ApplyPolicyCell>(txn, &after.stubbed())?;
    }
    Ok(after)
}

/// Widen the `rule_coverage_gaps` cell by `gaps`, in `txn` (a connect that
/// was handed a verdict which did not evaluate them). Empty `gaps` is a
/// no-op that does not touch the cell.
pub(super) fn widen_gaps(txn: &WriteTransaction, gaps: CoverageGaps) -> Result<(), StoreError> {
    if gaps.is_empty() {
        return Ok(());
    }
    let current = {
        let table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
        get::<CoverageGapsCell>(&table)?.ok_or(absent::<CoverageGapsCell>())?
    };
    let after = current.union(gaps);
    if after != current {
        put::<CoverageGapsCell>(txn, &after)?;
    }
    Ok(())
}

/// Widen the `passed_through_facts` cell by `facts`, in `txn` (a connect
/// that recorded them without the validator deriving them). Empty is a
/// no-op that does not touch the cell.
pub(super) fn widen_passed_through(
    txn: &WriteTransaction,
    facts: PassedThroughFacts,
) -> Result<(), StoreError> {
    if facts.is_empty() {
        return Ok(());
    }
    let current = {
        let table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
        get::<PassedThroughFactsCell>(&table)?.ok_or(absent::<PassedThroughFactsCell>())?
    };
    let after = current.union(facts);
    if after != current {
        put::<PassedThroughFactsCell>(txn, &after)?;
    }
    Ok(())
}

/// Read cell `C` from an open `properties` table.
///
/// `Ok(None)` if absent; [`StoreInvariant::CellCorrupt`] if present but not an
/// encoding of `C::Value`.
pub(super) fn get<C: PropertyCell>(
    table: &impl ReadableTable<&'static str, Blob<PropertyCellBytes>>,
) -> Result<Option<C::Value>, StoreError> {
    let Some(guard) = table.get(C::KEY).map_err(EngineError::Storage)? else {
        return Ok(None);
    };
    C::Value::decode(guard.value().bytes())
        .map(Some)
        .map_err(|cause| {
            StoreInvariant::CellCorrupt {
                key: C::KEY,
                fault: CellFault::Undecodable(cause),
            }
            .into()
        })
}

/// Write cell `C` in `txn`. Header cells are store-owned registers;
/// overwrite is the only operation, so this is not the keyed-table
/// `upsert` verb. Opens (creating if needed) the `properties` table for
/// the duration of the write.
pub(super) fn put<C: PropertyCell>(
    txn: &WriteTransaction,
    value: &C::Value,
) -> Result<(), StoreError> {
    let mut table = txn.open_table(PROPERTIES).map_err(EngineError::Table)?;
    table
        .insert(C::KEY, Raw::<PropertyCellBytes>::new(&value.encode()))
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
