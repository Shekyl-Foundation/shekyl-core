// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb schema map over the censused LMDB inventory (DRS-0 slice B).
//!
//! One `TableDefinition` per LMDB table, **derived from the X-macro
//! `SHEKYL_LMDB_TABLES` (`src/blockchain_db/lmdb/db_lmdb.cpp:317`) and nothing
//! else**. The denominator is counted from that macro; the bijection is gated
//! by `scripts/ci/check_redb_schema_bijection.py`. Key/value types that
//! reproduce LMDB order are gated by `scripts/ci/check_redb_schema_key_types.py`.
//! Slice A's per-table accumulator classes pin to the same X-macro; a name
//! that exists in only one of the two modules is a merge defect, not a
//! third list to maintain here.
//!
//! Walking `BlockchainDB`'s virtual interface is not the denominator, because
//! a table can exist without being on it. The instance that proved this:
//! until 2026-09-13 the settlement write path lived only on `BlockchainLMDB`,
//! so a schema built from the abstract interface would have shipped without a
//! write path LMDB has. SO-D8 has since promoted that path onto `BlockchainDB`
//! (`ARCHIVAL_SETTLEMENT_WRITER.md` §12), which closes that instance and not
//! the class — the X-macro stays the only authority.
//!
//! # Mapping rules, derived from LMDB open flags and comparators
//!
//! | LMDB | redb |
//! |---|---|
//! | `MDB_INTEGERKEY` | `u64` key (redb orders `u64` numerically) |
//! | `MDB_DUPSORT` | a zerokval collapse (below), **or** a keyed `(key, dup)` tuple — never a redb multimap (SOK-1) |
//! | `MDB_DUPFIXED` | storage hint only; no semantic effect |
//! | `compare_uint64` | `u64` ordering — numeric, same as `MDB_INTEGERKEY` |
//! | `compare_string` | `&str` — byte-lexicographic with a length tiebreak |
//! | `compare_hash32` | [`LmdbHashKey`] — **not** [`Hash32`], see that type |
//! | no flags, no comparator | `&[u8]` — byte-lexicographic |
//!
//! Default-flag tables that store `BE(x)` 8-byte keys are correctly mapped as
//! either `u64` or `&[u8]`: big-endian bytes compared lexicographically *are*
//! numeric order. The type gate leaves those unconstrained.
//!
//! # The zerokval collapse (a deliberate divergence, §6.4)
//!
//! Five tables — `block_heights`, `block_info`, `output_txs`, `spent_keys`,
//! `tx_indices` — store a **dummy 8-zero-byte key** and put the real
//! identifier in a fixed-size duplicate value, ordered by a custom dupsort
//! comparator. That exists to exploit LMDB's dup-sort B-tree; redb has no
//! DUPSORT, so the workaround has no purpose and the real identifier becomes
//! the redb **key**.
//!
//! This **preserves ordering rather than changing it**: the comparator moves
//! from duplicate-position to key-position and compares the same bytes the
//! same way. It is recorded as a divergence because the shape differs, not
//! because the semantics do.
//!
//! # Value types
//!
//! Every **map** value is one of four named shapes (`codec::shape`;
//! `DAEMON_REDB_STORE.md` §11.1(f)) — `&[u8]` is not a value type:
//!
//! - [`Coded<V>`] — rows are `V::encode` under a [`Canonical`] codec; the
//!   value `TypeName` is `shekyl::Coded<{V::NAME}>`. Per DRS-0 slice A the accumulator folds
//!   exactly that encoding, never storage bytes. Hash *values* are the
//!   identity type (`PrunableHash`), not a `Hash32`: a value carries no
//!   LMDB ordering, and `lmdb_order` is for orderings.
//! - [`Blob<K>`] — wire bytes the chain encodes and this crate does not
//!   re-codec (`blocks`, the tx segments, `properties`' per-key cells);
//!   [`BlobKind`] names the kind.
//! - [`Present`] — a set-table: the key is the member, the value is a
//!   zero-width witness (`spent_keys`).
//! - [`Unshaped`] — a censused table no Rust writer has reached. Its row
//!   type is uninhabited: catalogued (it has an ordinal), refused by the
//!   journal replay, **not seal-created** (`Restorable::SEALED = false`),
//!   **not insertable**. The increment that first writes the
//!   table replaces this with its codec and bumps `SCHEMA_VERSION`.
//!
//! There is no multimap in the catalogue: LMDB's one `DUPSORT` table,
//! `output_amounts`, is a keyed `(amount, amount_index)` tuple (S-OUT-KI
//! SOK-1) — the multimap had no seek within a key's members, and a set of
//! members ordered by a prefix is a composite key wearing a value's clothes.
//!
//! Keys are typed for **ordering** (`lmdb_order`); values for **codec**.
//! Both are checked by redb at `open_table` (`TypeName`), which covers a
//! definition drifting onto the wrong table; codec confusion inside a
//! table is closed by the Rust type — a `Coded<V>` reads and writes only
//! `Encoded<'_, V>` (`codec::shape` module docs, *Two guards*).
//! Write-pattern obligations (read before delete on set-shaped tables) are
//! DRS-E1; they live in `LMDB_WRITE_ATOMICITY_AUDIT.md` §12, not as a list
//! here.
//!
//! [`Canonical`]: crate::codec::Canonical
//! [`BlobKind`]: crate::codec::BlobKind
//! [`Present`]: crate::codec::Present
//!
//! # The catalogue is the declaration
//!
//! Every definition is declared through one `tables!` invocation, which
//! also emits [`catalogue`]: the same list as [`TableSpec`] rows — name
//! and the key/value [`TypeName`]s redb checks against the definition at
//! every `open_table`. Those facts are what a binary with a different
//! layout trips over, so they are what the table catalogue snapshot
//! (`codec::snapshot_tests`, rule 42) pins: adding, removing or re-keying
//! a table moves the snapshot and therefore requires the `SCHEMA_VERSION`
//! bump §11.1(b) owes. A definition cannot be added outside the invocation
//! without that module's source scan failing. The snapshot line spells
//! `map<key, value>`: the catalogue has one shape (rule 21 — a second
//! shape re-mints the word here with its table, not a reserved enum).
//!
//! # Ordinals, and the tables LMDB does not have
//!
//! The same invocation numbers its declarations: a table's
//! [`TableOrdinal`] is its position in the list, and the pop journal
//! (`undo_log`, S-CHAIN-W) names tables by ordinal rather than by name.
//! Reordering declarations would therefore replay old journal rows into
//! the wrong tables — which is why an ordinal change is a layout change:
//! the catalogue snapshot moves (each row carries its `#ordinal`),
//! `SCHEMA_VERSION` bumps, and the header seal refuses to open a file
//! written under the old numbering before any row is read. The journal
//! row carries no per-row version for that reason; the file-level seal is
//! the guard.
//!
//! **Removing a table is a bump too, not only reordering.** `UNDO_TARGETS`
//! is indexed by ordinal, so deleting a declaration silently renumbers
//! every table after it — the same hazard as a reorder, from an edit that
//! looks like a deletion. The snapshot catches both; and because the store
//! is rebuild-never-migrate (§11.1(a)), the bump *is* the resolution: a
//! file under the old numbering is refused, not renumbered. A future reader
//! who finds "bumped for a removal" in the history is looking at this
//! sentence's consequence, not over-caution.
//!
//! Two tables have no X-macro twin (`docs/completed/DRS_E1_SCHAIN_W.md` §5, SCW-11):
//! `undo_log`, the first, and `txs_pqc_auth_hash`, the second (S-CHAIN-R
//! amendment A3, `PDM-Q-F26`). Each is declared in [`RUST_ONLY_TABLES`] with
//! the reason it exists, and the bijection gate reads that map: a definition
//! with neither a twin **nor** a named reason is still red with the
//! extra-leg's original refusal, so the mirror assumption retires one table
//! at a time, never as a mode switch.
//!
//! Two X-macro tables have their twin in **another file** (DRS-E1 S-POOL,
//! `DRS_E1_SPOOL.md` §4): `txpool_meta` and `txpool_blob` are `pool_meta`
//! and `pool_blob` in the pool file (`crate::pool::schema`), because
//! `DAEMON_REDB_STORE.md` §5.1 ruled the pool out of the consensus store
//! file. Each is declared in [`MIRRORED_ELSEWHERE`] with the twin's name and
//! the reason; the bijection gate reads that map too, so a censused table
//! with no definition here is red unless it says where its twin is, and an
//! entry that names a twin no other file defines is red as well. The class
//! table stays the LMDB inventory: both keep their `Excluded` rows there.
//!
//! # The seal creates every table with a writer
//!
//! From S-CHAIN-R's layout commit (amendment A2, SCR-17) `header::seal` opens
//! — and so creates — every table whose value shape is not [`Unshaped`], in
//! the create transaction, and `header::verify` refuses a sealed file that
//! lacks one (SI-7, the table named as the cell). So a reader that meets
//! `TableDoesNotExist` on a chain table is looking at a file this store did
//! not write, and *absent table* never has to be read as *empty table*. The
//! set is derived from the shapes, not kept as a second list: a table gets a
//! writer by leaving `Unshaped`, and is sealed by the same edit.

use redb::{TableDefinition, TableHandle, TypeName};

use shekyl_types::{BlockHeight, CurveTreeRoot, PqcAuthHash, PrunableHash, TreeLeaf};
use shekyl_units::AtomicUnits;

use crate::codec::{
    AltBlock, AttestationWitnessBytes, Blob, BlockBody, BlockInfo, BondRecord, Coded,
    CurveTreeState, LayerHash, OutKey, OutTx, Present, PropertyCellBytes, RMarket, RuleSetInForce,
    SigmaWorkMilli, TxIndex, TxOutputIndices, TxPqcAuthsSegment, TxPrunableSegment,
    TxPrunedSegment, UndoLog, Unshaped,
};
use crate::lmdb_order::LmdbHashKey;
use crate::store::undo::UndoTarget;

/// A table's position in the `tables!` declaration list — the identity the
/// pop journal records (module docs, *Ordinals*).
///
/// Dense from zero, one per catalogued table. Minted only by
/// [`ordinal_of`]; the journal codec reads one back from the file and the
/// replay resolves it against the catalogue, refusing an index it does not
/// have rather than guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableOrdinal(u32);

impl TableOrdinal {
    /// The raw index, as the journal codec stores it.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }

    /// Wrap a raw index read from the file. Not a lookup: the replay is
    /// where an out-of-range index is refused.
    #[must_use]
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }
}

impl core::fmt::Display for TableOrdinal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match undo_target(*self) {
            Some(target) => write!(f, "#{} ({})", self.0, target.name()),
            None => write!(f, "#{} (no such table)", self.0),
        }
    }
}

/// The ordinal of the catalogued table named `name`, or `None` if no
/// declaration carries that name.
#[must_use]
pub fn ordinal_of(name: &str) -> Option<TableOrdinal> {
    UNDO_TARGETS
        .iter()
        .position(|target| target.name() == name)
        .and_then(|i| u32::try_from(i).ok())
        .map(TableOrdinal)
}

/// The table `ordinal` names, as the journal replays into it.
#[must_use]
pub(crate) fn undo_target(ordinal: TableOrdinal) -> Option<&'static dyn UndoTarget> {
    UNDO_TARGETS.get(usize::try_from(ordinal.0).ok()?).copied()
}

/// X-macro tables whose redb twin is defined in **another file of this
/// crate**, as `(lmdb_name, twin_name, reason)`. Read by
/// `check_redb_schema_bijection.py`: every entry must be in the X-macro,
/// must **not** have a definition in this file, its twin must be a
/// definition in `crate::pool::schema`, and two entries must not name the
/// same twin; `check_redb_schema_key_types.py` has no definition here to
/// constrain and is told so. The class table (`accumulator/class.rs`) is
/// the LMDB inventory and keeps a row for each.
pub const MIRRORED_ELSEWHERE: &[(&str, &str, &str)] = &[
    (
        "txpool_meta",
        "pool_meta",
        "the pool is not consensus state and not reconstructible from blocks, so it lives in \
         its own discardable file (DAEMON_REDB_STORE.md §5.1, built by DRS-E1 S-POOL): the \
         typed record is `pool_meta` in `crate::pool`",
    ),
    (
        "txpool_blob",
        "pool_blob",
        "the pool entry's transaction bytes, beside its record in the pool file for the same \
         reason (DAEMON_REDB_STORE.md §5.1; DRS-E1 S-POOL): `pool_blob` in `crate::pool`",
    ),
];

/// X-macro tables whose bytes live as a **field of another table's
/// record** in this file, as `(lmdb_name, host_table, reason)` — the
/// bijection gate's fourth direction (DRS-E1 S-ALT, SAL-2; `SAL-Q6`: its
/// own direction, because a twin *table* and a host *field* are different
/// claims and the gate should say which it checked). Read by
/// `check_redb_schema_bijection.py`: every entry must be in the X-macro,
/// must **not** have a definition in this file, and its host must be a
/// definition in this file; `check_redb_schema_key_types.py` has no
/// definition here to constrain and its floor moved with the fold. The
/// class table (`accumulator/class.rs`) is the LMDB inventory and keeps a
/// row for each.
pub const FOLDED_INTO: &[(&str, &str, &str)] = &[(
    "archival_alt_attestation_witness",
    "alt_blocks",
    "the reorg-survival attestation witness is an attribute of the alt block it is keyed by \
     (ARCHIVAL_CREDIT_WIRE.md §3 CW-2: written beside it, removed with it, never outliving \
     it), so it is a field of `AltBlock` rather than a second hash-keyed table (DRS-E1 S-ALT, \
     `SAR-Q5`, `SAL-Q2`): `AltBlock::attestation_witness`",
)];

/// Tables this crate defines that have **no** X-macro twin, each with the
/// reason it exists. Read by `check_redb_schema_bijection.py` (a definition
/// is either mirrored or named here — never silently extra) and by
/// `check_redb_schema_key_types.py` (no LMDB flags to derive a key type
/// from). Out of the digest domain by construction: the accumulator's
/// class table is the LMDB inventory, and a table absent from it with a
/// reason here is a named exclusion, not an omission.
pub const RUST_ONLY_TABLES: &[(&str, &str)] = &[
    (
        "undo_log",
        "the pop journal: one LIFO row of pre-images per connected height, replacing the C++ \
         per-surface journals (C2-R8 Q5); a function of the journaled writes, so two correct \
         stores of one chain agree on it by construction and it is not folded",
    ),
    (
        "txs_pqc_auth_hash",
        "the txid's third component per 4-part transaction (PDM-Q-F26, DRS §7.7): the persisted \
         digest that lets PDM-Q6 discard the pqc_auths segment; the C++ store never held it \
         because it never discarded that segment. Out of the digest domain: the txid the \
         digest already folds commits to the same value",
    ),
];

/// One table's identity as redb records it in the file: name and the
/// key/value type names it validates at `open_table`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableSpec {
    /// The redb table name (the LMDB table name, verbatim).
    pub name: String,
    /// The key type as redb names it on disk.
    pub key: TypeName,
    /// The value type as redb names it on disk.
    pub value: TypeName,
}

/// Project a definition into its [`TableSpec`]. Private: the only caller
/// is the `catalogue` the macro below emits.
trait Catalogued {
    fn spec(&self) -> TableSpec;
}

impl<K: redb::Key + 'static, V: redb::Value + 'static> Catalogued for TableDefinition<'_, K, V> {
    fn spec(&self) -> TableSpec {
        TableSpec {
            name: TableHandle::name(self).to_owned(),
            key: K::type_name(),
            value: V::type_name(),
        }
    }
}

/// Declare the table definitions **and** the catalogue over them from one
/// list. The items are written as ordinary `pub const` declarations so the
/// two Python gates that read this file (`check_redb_schema_bijection.py`,
/// `check_redb_schema_key_types.py`) parse them unchanged.
macro_rules! tables {
    (
        $(
            $(#[$attr:meta])*
            pub const $name:ident : $ty:ty = $def:expr ;
        )+
    ) => {
        $(
            $(#[$attr])*
            pub const $name: $ty = $def;
        )+

        /// Every table this crate defines, one [`TableSpec`] each, in
        /// declaration order. Non-empty by construction.
        #[must_use]
        pub fn catalogue() -> Vec<TableSpec> {
            vec![$($name.spec(),)+]
        }

        /// Every table as a journal-replay target, in the same order as
        /// [`catalogue`] — index *i* here **is** [`TableOrdinal`] *i*. A
        /// table whose key or value type cannot be checked before
        /// `Value::from_bytes` does not compile into this list, so a
        /// declaration that the journal could not replay is refused at
        /// build time rather than at pop time.
        pub(crate) const UNDO_TARGETS: &[&dyn UndoTarget] = &[$(&$name,)+];
    };
}

tables! {
    /// `blocks` — INTEGERKEY; height → block blob.
    pub const BLOCKS: TableDefinition<u64, Blob<BlockBody>> = TableDefinition::new("blocks");

    /// `block_heights` — zerokval collapse: dup hash (`compare_hash32`) becomes the key.
    pub const BLOCK_HEIGHTS: TableDefinition<LmdbHashKey, Coded<BlockHeight>> = TableDefinition::new("block_heights");

    /// `block_info` — zerokval collapse: dup height (`compare_uint64`) becomes the key.
    pub const BLOCK_INFO: TableDefinition<u64, Coded<BlockInfo>> = TableDefinition::new("block_info");

    /// `txs` — INTEGERKEY. Dead (DRS-W4): no runtime rows.
    pub const TXS: TableDefinition<u64, Unshaped> = TableDefinition::new("txs");

    /// `txs_pruned` — INTEGERKEY; tx_id → pruned blob.
    pub const TXS_PRUNED: TableDefinition<u64, Blob<TxPrunedSegment>> = TableDefinition::new("txs_pruned");

    /// `txs_pqc_auths` — INTEGERKEY + `compare_uint64` (numeric, same as INTEGERKEY).
    pub const TXS_PQC_AUTHS: TableDefinition<u64, Blob<TxPqcAuthsSegment>> = TableDefinition::new("txs_pqc_auths");

    /// `txs_prunable` — INTEGERKEY. Node-local; excluded from the accumulator.
    pub const TXS_PRUNABLE: TableDefinition<u64, Blob<TxPrunableSegment>> = TableDefinition::new("txs_prunable");

    /// `txs_prunable_hash` — INTEGERKEY; 1:1 hash value. A value carries no
    /// LMDB ordering, so it is the identity type, not a `Hash32`.
    pub const TXS_PRUNABLE_HASH: TableDefinition<u64, Coded<PrunableHash>> =
        TableDefinition::new("txs_prunable_hash");

    /// `tx_indices` — zerokval collapse: dup tx hash (`compare_hash32`) becomes the key.
    pub const TX_INDICES: TableDefinition<LmdbHashKey, Coded<TxIndex>> = TableDefinition::new("tx_indices");

    /// `tx_outputs` — INTEGERKEY; tx_id → output indices.
    pub const TX_OUTPUTS: TableDefinition<u64, Coded<TxOutputIndices>> = TableDefinition::new("tx_outputs");

    /// `output_txs` — zerokval collapse: dup output id (`compare_uint64`) becomes the key.
    pub const OUTPUT_TXS: TableDefinition<u64, Coded<OutTx>> = TableDefinition::new("output_txs");

    /// `output_amounts` — LMDB's `DUPSORT` table as a keyed tuple: key
    /// `(amount, amount_index)`, the pair LMDB keyed by (`MDB_INTEGERKEY` on
    /// `amount`, `compare_uint64` on the member prefix), so the tuple's
    /// lexicographic order over two numeric `u64`s **is** LMDB's order. Not
    /// a multimap: redb has no seek within a key's value set, so a point
    /// read on the ported multimap walked the whole amount-0 bucket
    /// (S-OUT-KI SOK-1); `get(&(0, i))` is O(log n). The amount dimension
    /// is carried, not chosen, while R8b-2 is open (`DRS_E1_SOUT_KI.md` §3.4).
    pub const OUTPUT_AMOUNTS: TableDefinition<(u64, u64), Coded<OutKey>> =
        TableDefinition::new("output_amounts");

    /// `spent_keys` — zerokval collapse: dup key image (`compare_hash32`) becomes the key.
    /// A set-table: the key is the member; [`Present`] is the zero-width witness.
    pub const SPENT_KEYS: TableDefinition<LmdbHashKey, Present> = TableDefinition::new("spent_keys");

    /// `alt_blocks` — key order `compare_hash32`; block hash → the alt
    /// block's record, bytes and reorg-survival witness in one row (S-ALT
    /// AL1–AL7, `DRS_E1_SALT.md` §3; `SAL-Q2`). Not chain state (§11.2):
    /// `Excluded` from every digest, written outside any pop recording.
    pub const ALT_BLOCKS: TableDefinition<LmdbHashKey, Coded<AltBlock>> =
        TableDefinition::new("alt_blocks");

    /// `hf_starting_heights` — default flags. Dead (DRS-W5): no runtime rows.
    pub const HF_STARTING_HEIGHTS: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("hf_starting_heights");

    /// `hf_versions` — INTEGERKEY; height → hf version.
    pub const HF_VERSIONS: TableDefinition<u64, Coded<RuleSetInForce>> =
        TableDefinition::new("hf_versions");

    /// `properties` — `compare_string` == byte-lex + length tiebreak == `&str` order.
    /// The one per-key codec: each `PropertyCell` names its value's, so the
    /// table is a `Blob` and strictness lives where the key is.
    pub const PROPERTIES: TableDefinition<&str, Blob<PropertyCellBytes>> = TableDefinition::new("properties");

    /// `block_burn` — INTEGERKEY; height → units burned, present only when non-zero.
    pub const BLOCK_BURN: TableDefinition<u64, Coded<AtomicUnits>> = TableDefinition::new("block_burn");

    /// `archival_serve_credit` — default flags in LMDB over the 56-byte
    /// packed key `P_id ‖ BE64(shard) ‖ BE64(epoch) ‖ BE64(height)`; here the
    /// tuple `([u8; 32], u64, u64, u64)`, which redb orders component-wise —
    /// exactly the packed key's lexicographic order — with nothing to pin
    /// (`ServeCreditKey`, `SCU-Q3`'s precedent). A row is a pass bit:
    /// `Present`. S-ARCH (E4 writes; A3–A5 read).
    pub const ARCHIVAL_SERVE_CREDIT: TableDefinition<([u8; 32], u64, u64, u64), Present> =
        TableDefinition::new("archival_serve_credit");

    /// `archival_settlement` — default flags. On the abstract interface since
    /// 2026-09-13 (SO-D8 promotion); was `BlockchainLMDB`-only before that.
    pub const ARCHIVAL_SETTLEMENT: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_settlement");

    /// `archival_attestation_witness` — INTEGERKEY; a block's stored witness
    /// bytes, absent when the attestation set was empty (never an empty row).
    /// S-ARCH (A10).
    pub const ARCHIVAL_ATTESTATION_WITNESS: TableDefinition<u64, Blob<AttestationWitnessBytes>> =
        TableDefinition::new("archival_attestation_witness");

    /// `archival_bond` — default flags; keyed by the 32-byte `p_canonical_id`,
    /// one `BondRecord` per persona (S-ARCH A1; SI-14 on decode).
    pub const ARCHIVAL_BOND: TableDefinition<[u8; 32], Coded<BondRecord>> =
        TableDefinition::new("archival_bond");

    /// `archival_shard_segment` — default flags, `BE(x)` keys (u64 preserves numeric order).
    pub const ARCHIVAL_SHARD_SEGMENT: TableDefinition<u64, Unshaped> =
        TableDefinition::new("archival_shard_segment");

    /// `archival_slash_applied` — default flags.
    pub const ARCHIVAL_SLASH_APPLIED: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_slash_applied");

    /// `archival_slash_log` — default flags.
    pub const ARCHIVAL_SLASH_LOG: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_slash_log");

    /// `archival_emission_claim_log` — default flags.
    pub const ARCHIVAL_EMISSION_CLAIM_LOG: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_emission_claim_log");

    /// `archival_bond_unbond_log` — default flags.
    pub const ARCHIVAL_BOND_UNBOND_LOG: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_bond_unbond_log");

    /// `archival_bond_holdings_update_log` — default flags.
    pub const ARCHIVAL_BOND_HOLDINGS_UPDATE_LOG: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_bond_holdings_update_log");

    /// `archival_bond_reinstate_log` — default flags.
    pub const ARCHIVAL_BOND_REINSTATE_LOG: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("archival_bond_reinstate_log");

    /// `archival_r_market` — default flags over `BE64(shard) ‖ BE64(epoch)`;
    /// here the tuple `(u64, u64)`, the same order. The co-holder count frozen
    /// at epoch close; absent is an epoch that never closed (S-ARCH A6).
    pub const ARCHIVAL_R_MARKET: TableDefinition<(u64, u64), Coded<RMarket>> =
        TableDefinition::new("archival_r_market");

    /// `archival_sigma_work` — default flags, `BE(x)` keys (u64 preserves numeric
    /// order). `Σwork(E)` frozen at epoch close (S-ARCH A7).
    pub const ARCHIVAL_SIGMA_WORK: TableDefinition<u64, Coded<SigmaWorkMilli>> =
        TableDefinition::new("archival_sigma_work");

    /// `archival_epoch_close_log` — default flags, `BE(x)` keys (u64 preserves numeric order).
    pub const ARCHIVAL_EPOCH_CLOSE_LOG: TableDefinition<u64, Unshaped> =
        TableDefinition::new("archival_epoch_close_log");

    /// `archival_budget_accrual` — default flags, `BE(x)` keys (u64 preserves numeric order).
    pub const ARCHIVAL_BUDGET_ACCRUAL: TableDefinition<u64, Unshaped> =
        TableDefinition::new("archival_budget_accrual");

    /// `archival_budget` — default flags, `BE(x)` keys (u64 preserves numeric
    /// order). The frozen `budget(E)` close row (S-ARCH A8).
    pub const ARCHIVAL_BUDGET: TableDefinition<u64, Coded<AtomicUnits>> =
        TableDefinition::new("archival_budget");

    /// `pending_tree_leaves` — default flags; composite BE keys.
    pub const PENDING_TREE_LEAVES: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("pending_tree_leaves");

    /// `pending_tree_drain` — default flags; composite BE keys.
    pub const PENDING_TREE_DRAIN: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("pending_tree_drain");

    /// `block_pending_additions` — default flags; composite BE keys.
    pub const BLOCK_PENDING_ADDITIONS: TableDefinition<&[u8], Unshaped> =
        TableDefinition::new("block_pending_additions");

    /// `output_to_leaf` — INTEGERKEY.
    pub const OUTPUT_TO_LEAF: TableDefinition<u64, Unshaped> = TableDefinition::new("output_to_leaf");

    /// `leaf_to_output` — INTEGERKEY.
    pub const LEAF_TO_OUTPUT: TableDefinition<u64, Unshaped> = TableDefinition::new("leaf_to_output");

    /// `curve_tree_leaves` — INTEGERKEY; `TreePosition` (as `u64`, the key
    /// contract of [`crate::ids`]) → the stored 128-byte leaf. Dense over
    /// `[0, leaf_count)` (SI-11). S-CURVE.
    pub const CURVE_TREE_LEAVES: TableDefinition<u64, Coded<TreeLeaf>> =
        TableDefinition::new("curve_tree_leaves");

    /// `curve_tree_layers` — `(layer, chunk)` → the chunk's Selene hash.
    /// [`crate::ids::LayerChunk::key`] assembles the tuple; layer-major
    /// order is that tuple's (`SCU-Q3`). Derived: recomputed from leaves,
    /// not folded. S-CURVE.
    pub const CURVE_TREE_LAYERS: TableDefinition<(u8, u64), Coded<LayerHash>> =
        TableDefinition::new("curve_tree_layers");

    /// `curve_tree_meta` — **one row** under the unit key: the tree's
    /// summary (`SCU-Q1`), written `EMPTY` by the seal so absence is a fault
    /// and never a default (SCU-1). S-CURVE.
    pub const CURVE_TREE_META: TableDefinition<(), Coded<CurveTreeState>> =
        TableDefinition::new("curve_tree_meta");

    /// `curve_tree_checkpoints` — INTEGERKEY. Derived: recomputed, not folded.
    pub const CURVE_TREE_CHECKPOINTS: TableDefinition<u64, Unshaped> =
        TableDefinition::new("curve_tree_checkpoints");

    /// `curve_tree_roots` — INTEGERKEY.
    pub const CURVE_TREE_ROOTS: TableDefinition<u64, Coded<CurveTreeRoot>> = TableDefinition::new("curve_tree_roots");

    /// `undo_log` — **Rust-only** ([`RUST_ONLY_TABLES`]); height → the
    /// [`UndoLog`](crate::codec::UndoLog) of pre-images `connect` recorded
    /// at that height, replayed in reverse by `pop` (C2-R8 Q5; register row
    /// SI-6). Appended when added so no existing ordinal moved; a later
    /// table is likewise appended, never inserted.
    pub const UNDO_LOG: TableDefinition<u64, Coded<UndoLog>> = TableDefinition::new("undo_log");

    /// `txs_pqc_auth_hash` — **Rust-only** ([`RUST_ONLY_TABLES`]); tx_id →
    /// the txid's third component, `keccak256(varint(count) ‖ auths)`, for
    /// every 4-part transaction (`PDM-Q-F26`; S-CHAIN-R amendment A3). Row
    /// present ⇔ txid 4-part, written by `connect` beside
    /// `txs_prunable_hash`. A prune of the `txs_pqc_auths` segment does
    /// **not** delete this digest — a row without its segment is
    /// *discarded*, not a fault (`PDM-Q-F26` leg 3). `pop` reverses the
    /// journaled insert with the rest of the block. Appended last
    /// (ordinal 50).
    pub const TXS_PQC_AUTH_HASH: TableDefinition<u64, Coded<PqcAuthHash>> =
        TableDefinition::new("txs_pqc_auth_hash");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinals_are_the_catalogue_positions() {
        let catalogue = catalogue();
        assert_eq!(catalogue.len(), UNDO_TARGETS.len());
        for (i, spec) in catalogue.iter().enumerate() {
            let ordinal =
                ordinal_of(&spec.name).unwrap_or_else(|| panic!("{} has no ordinal", spec.name));
            assert_eq!(ordinal.index(), u32::try_from(i).expect("fits"));
            assert_eq!(
                undo_target(ordinal).map(UndoTarget::name),
                Some(spec.name.as_str())
            );
        }
        assert_eq!(ordinal_of("not_a_table"), None);
        let past_end = TableOrdinal::from_index(u32::try_from(catalogue.len()).expect("fits"));
        assert!(undo_target(past_end).is_none());
        assert_eq!(
            past_end.to_string(),
            format!("#{} (no such table)", catalogue.len())
        );
    }

    /// The pin that makes "append, never insert" checkable: the ordinal of
    /// every table declared before this test was written. A reorder that
    /// moves one of these is a layout change and must move the catalogue
    /// snapshot and `SCHEMA_VERSION` with it — this test is the reminder
    /// that fires before the snapshot diff does.
    #[test]
    fn pinned_ordinals_have_not_moved() {
        let pinned: &[(&str, u32)] = &[
            ("blocks", 0),
            ("block_heights", 1),
            ("block_info", 2),
            ("tx_indices", 8),
            ("output_amounts", 11),
            ("spent_keys", 12),
            // Layout 12: `txpool_meta` (13) and `txpool_blob` (14) left for
            // the pool file (S-POOL), so everything after `spent_keys`
            // moved up by two — the bump this test exists to make visible.
            ("hf_versions", 15),
            ("properties", 16),
            ("block_burn", 17),
            // Layout 13: `archival_alt_attestation_witness` (21) folded
            // into `alt_blocks` (S-ALT), so everything after it moved up by
            // one.
            ("curve_tree_roots", 43),
            ("undo_log", 44),
        ];
        for &(name, index) in pinned {
            assert_eq!(
                ordinal_of(name).map(TableOrdinal::index),
                Some(index),
                "{name}: ordinal moved — a declaration was inserted or reordered above it"
            );
        }
    }

    #[test]
    fn mirrored_elsewhere_tables_are_absent_here_and_present_in_the_pool_file() {
        let here: Vec<String> = catalogue().into_iter().map(|s| s.name).collect();
        let pool: Vec<String> = crate::pool::schema::catalogue()
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert!(!MIRRORED_ELSEWHERE.is_empty());
        for &(name, twin, reason) in MIRRORED_ELSEWHERE {
            assert!(
                !here.iter().any(|c| c == name),
                "{name}: named as mirrored elsewhere but defined in this file"
            );
            assert!(
                pool.iter().any(|c| c == twin),
                "{name}: its twin `{twin}` is not a pool-file table"
            );
            assert!(
                reason.split_whitespace().count() >= 8,
                "{name}: a mirrored table's reason is a sentence, not a token"
            );
            assert!(
                crate::accumulator::class_for_table(name).is_some(),
                "{name}: the class table is the LMDB inventory and keeps this row"
            );
        }
    }

    #[test]
    fn folded_tables_are_absent_here_and_their_host_is_defined() {
        let here: Vec<String> = catalogue().into_iter().map(|s| s.name).collect();
        assert!(!FOLDED_INTO.is_empty());
        for &(name, host, reason) in FOLDED_INTO {
            assert!(
                !here.iter().any(|c| c == name),
                "{name}: named as folded but defined in this file"
            );
            assert!(
                here.iter().any(|c| c == host),
                "{name}: its host `{host}` is not a table in this file"
            );
            assert!(
                reason.split_whitespace().count() >= 8,
                "{name}: a folded table's reason is a sentence, not a token"
            );
            assert!(
                crate::accumulator::class_for_table(name).is_some(),
                "{name}: the class table is the LMDB inventory and keeps this row"
            );
        }
    }

    #[test]
    fn rust_only_tables_are_catalogued_and_carry_a_reason() {
        let catalogued: Vec<String> = catalogue().into_iter().map(|s| s.name).collect();
        assert!(!RUST_ONLY_TABLES.is_empty());
        for &(name, reason) in RUST_ONLY_TABLES {
            assert!(
                catalogued.iter().any(|c| c == name),
                "{name}: named Rust-only but not declared"
            );
            assert!(
                reason.split_whitespace().count() >= 8,
                "{name}: a Rust-only table's reason is a sentence, not a token"
            );
            assert!(
                crate::accumulator::class_for_table(name).is_none(),
                "{name}: a Rust-only table has no LMDB class row; its exclusion is the reason here"
            );
        }
    }
}
