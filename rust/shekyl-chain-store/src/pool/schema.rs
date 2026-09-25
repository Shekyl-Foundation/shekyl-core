// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file's tables — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §4).
//!
//! Three tables in a file of their own (`DAEMON_REDB_STORE.md` §5.1: *the
//! pool does not live in the consensus store file*). The two the C++ keeps
//! in the chain's LMDB env as `txpool_meta` / `txpool_blob` are here as
//! `pool_meta` / `pool_blob`, typed; the third is the file's header. None of
//! them is in [`crate::schema`]'s catalogue, none is a journal target, and no
//! digest reaches them — the pool is not chain state (§11.2).
//!
//! # Keyed by the transaction hash, in its natural order
//!
//! The consensus file keeps LMDB's `compare_hash32` order on its hash-keyed
//! tables (`LmdbHashKey`) so the digest oracle can walk both stores in one
//! order. The pool file has no oracle and no LMDB twin to stay in step
//! with, and no `for_all_txpool_txes` caller depends on iteration order
//! (SPL-8), so the key is the hash's own bytes (`SCU-Q3`: remove the thing
//! that needs pinning).
//!
//! # Two tables, deliberately (§3.5)
//!
//! The meta row is rewritten on every relay tick, readiness probe and class
//! upgrade; the blob is written once. Under copy-on-write a single row would
//! copy the transaction bytes on every clock tick. Same split as the C++,
//! with the pairing made an invariant (SI-16) rather than a `DB_ERROR`
//! string at the read.

use redb::{TableDefinition, TableHandle, Value};
use shekyl_store_codec::{Blob, BlobKind, Coded};

use crate::codec::PropertyCellBytes;
use crate::schema::TableSpec;

use crate::codec::PoolRecord;

/// The raw transaction bytes of a pool entry, unparsed — the store does not
/// parse a transaction (S-CHAIN-R's `RawBlockBytes` discipline). Empty is
/// refused: a pool entry is a transaction.
#[derive(Debug)]
pub struct PoolTxBytes;

impl BlobKind for PoolTxBytes {
    const NAME: &'static str = "pool_tx";

    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.is_empty() {
            return Err("a pool entry is a transaction; an empty blob is no entry");
        }
        Ok(())
    }
}

/// `pool_meta` — `txid → PoolRecord`. Written by `insert` and `update`,
/// deleted by `remove`.
pub const POOL_META: TableDefinition<[u8; 32], Coded<PoolRecord>> =
    TableDefinition::new("pool_meta");

/// `pool_blob` — `txid → transaction bytes`. Written by `insert` only (the
/// blob is immutable for the entry's life), deleted by `remove`.
pub const POOL_BLOB: TableDefinition<[u8; 32], Blob<PoolTxBytes>> =
    TableDefinition::new("pool_blob");

/// `pool_header` — the file's own header cells: the layout version it was
/// sealed at ([`super::POOL_VERSION_KEY`]). Store-owned; no public write
/// path reaches it.
pub const POOL_HEADER: TableDefinition<&str, Blob<PropertyCellBytes>> =
    TableDefinition::new("pool_header");

/// Every table the pool file defines, one [`TableSpec`] each, in
/// declaration order — the pool file's catalogue, pinned by
/// `schemas/pool_tables.snap` under the crate's `SCHEMA_VERSION`.
#[must_use]
pub fn catalogue() -> Vec<TableSpec> {
    fn spec<K: redb::Key + 'static, V: Value + 'static>(
        t: &TableDefinition<'_, K, V>,
    ) -> TableSpec {
        TableSpec {
            name: TableHandle::name(t).to_owned(),
            key: K::type_name(),
            value: V::type_name(),
        }
    }
    vec![spec(&POOL_META), spec(&POOL_BLOB), spec(&POOL_HEADER)]
}
