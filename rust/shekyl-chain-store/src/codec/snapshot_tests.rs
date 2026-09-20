// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rule-42 codec gate for the chain store.
//!
//! One committed fixture snapshot per codec this store's layout uses,
//! under `rust/shekyl-chain-store/schemas/<NAME>.snap`: the codec's name
//! and width, then representative values with their canonical encodings
//! in hex. That set is the codecs implemented here **plus** the ones this
//! store persists whose impls moved to `shekyl-store-codec` — their bytes
//! are still this store's layout and still the digest's fold input, so
//! their fixtures stay here. The per-codec tests re-encode the fixtures and compare against the
//! committed text, then decode the encoding back and compare against the
//! value, so both directions are pinned to the bytes reviewers approved.
//!
//! # Why a fixture KAT and not a type schema
//!
//! The wallet's gate (`shekyl-engine-state/src/schema_snapshot.rs`)
//! snapshots a derived `postcard` schema, because there the *derive* is
//! the encoding. Here the encodings are written by hand and the digest
//! folds them (`DAEMON_REDB_STORE.md` §11.1(b)), so what must not move is
//! the **bytes**, and the snapshot is of bytes.
//!
//! # The catalogues are snapshots too
//!
//! §11.1(b) owes a version bump for a table added, removed or re-keyed,
//! and for a `properties` cell added, re-keyed, re-scoped or re-typed —
//! none of which need move a codec fixture's bytes. So:
//!
//! - `schemas/tables.snap` pins [`schema::catalogue`]: one row per
//!   definition with its name, its declaration ordinal (the pop journal's
//!   table identity), its shape and the key/value `TypeName`s redb checks
//!   at `open_table`.
//! - `schemas/properties.snap` pins [`PROPERTY_CELLS`]: one row per cell
//!   with its key, [`CellScope`] and value-codec name. A new
//!   [`ChainState`](super::ChainState) cell is digest-domain growth even
//!   when its value codec already has a fixture.
//!
//! A layout change of either kind moves that text and enters the same
//! paired-bump gate as the codec bytes.
//!
//! # One version, so the pairing is a glob
//!
//! Every codec in this crate pairs with the same constant —
//! [`SCHEMA_VERSION`] — because the store has one layout version
//! (§11.1(a)). `.github/workflows/schema-snapshot.yml` therefore enforces
//! *any change under `schemas/` ⟹ `SCHEMA_VERSION` has a greater value
//! in the same PR*, with no per-codec registry to keep in sync. What this
//! module still has to guard is that the snapshot **set** is exactly the
//! registered codecs' names plus the catalogues, and that no codec
//! implemented here escapes registration
//! ([`every_canonical_impl_has_a_snapshot`] — read its *Why containment
//! here and equality there* for what the move did and did not cost), and
//! that the workflow is actually wired — runs this whole module,
//! and parses the declaration in the grammar it is written in
//! ([`workflow_gates_this_crate`]). A gate whose subject is absent is not a
//! gate (rule 47).
//!
//! # Regenerating
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests
//! ```
//!
//! then bump [`SCHEMA_VERSION`] in `src/codec/schema_version.rs` and re-run
//! **without** the variable. [`codec_snapshot_assertions_are_armed`] fails
//! while it is set, so a regeneration run can never pass as an assertion
//! run.

// Whole-file test module: the parent already gates it with
// `#[cfg(test)] mod snapshot_tests;`, and this inner marker is how the
// file declares the same thing to `build.yml`'s debug-macro lint, whose
// scan keys on the first `#[cfg(test)]` / `#![cfg(test)]` in the file. The
// regeneration driver's `eprintln!` is test-only output and must not read
// as production.
#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::apply_policy::ArchivalFamily;
use crate::family_set::FamilySet;
use crate::lmdb_order::Hash32;
use crate::schema;

use super::{
    post_image, BlockInfo, Canonical, CoverageGaps, OutKey, OutTx, PassedThroughFacts, ProbeCell,
    PropertyCell, RuleSetInForce, SchemaVersion, SettlementEpochBlocks, TxIndex, TxOutputIndices,
    UndoEntry, UndoLog, PROPERTY_CELLS, SCHEMA_VERSION,
};
use crate::ids::{AmountIndex, OutputStorageId, TxStorageId};
use crate::schema::TableOrdinal;
use shekyl_chain_rules::{CenRow, RuleSetId};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    BlockHash, BlockHeight, BlockWeight, CommitmentBytes, CurveTreeRoot, LongTermWeight,
    OneTimePubkey, OutputIndexInTx, PqcAuthHash, PrunableHash, Timestamp, TxHash,
};
use shekyl_units::AtomicUnits;

/// Catalogue snapshot stems under `schemas/`. Not codec names;
/// [`every_canonical_impl_has_a_snapshot`] holds the two namespaces apart.
const TABLE_CATALOGUE_SNAP: &str = "tables";
const PROPERTY_CATALOGUE_SNAP: &str = "properties";
const CATALOGUE_SNAPS: &[&str] = &[TABLE_CATALOGUE_SNAP, PROPERTY_CATALOGUE_SNAP];

/// The `cargo test` filter that selects exactly this module — what the
/// workflow's assert job runs. Pinned here so [`workflow_gates_this_crate`]
/// can hold the workflow to it and hold it to `module_path!()`.
const TEST_FILTER: &str = "codec::snapshot_tests";

const SNAPSHOT_HEADER: &str =
    "# shekyl-chain-store canonical codec snapshot (rule 42). Do not edit by hand:\n\
     #   UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests\n\
     # and bump SCHEMA_VERSION in src/codec/schema_version.rs in the same PR.\n";

/// A codec's representative values.
trait Fixtures: Canonical + PartialEq + core::fmt::Debug {
    fn fixtures() -> Vec<(&'static str, Self)>;
}

impl Fixtures for u8 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![("zero", 0), ("one", 1), ("high_bit", 0x80), ("max", 0xff)]
    }
}

impl Fixtures for u64 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", 0),
            ("one", 1),
            // Every byte distinct, so the snapshot is a byte-order witness:
            // a big-endian regression reads `0807060504030201` here.
            ("byte_order", 0x0102_0304_0506_0708),
            ("max", u64::MAX),
        ]
    }
}

impl Fixtures for Hash32 {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", Hash32::from_bytes([0; 32])),
            (
                "ascending",
                Hash32::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
            ("max", Hash32::from_bytes([0xff; 32])),
        ]
    }
}

impl Fixtures for SchemaVersion {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Literals, not `SCHEMA_VERSION`: the snapshot pins the *codec*,
        // and must not move just because the version it pairs with did.
        vec![
            ("zero", SchemaVersion::new(0)),
            ("one", SchemaVersion::new(1)),
            ("byte_order", SchemaVersion::new(0x0102_0304_0506_0708)),
        ]
    }
}

impl Fixtures for FamilySet {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let mut fixtures = vec![("empty", FamilySet::EMPTY)];
        // One-hot per family, labelled by the table it owns, in X-macro
        // order: the snapshot IS the family→bit assignment. A persisted
        // provenance mask is only readable while that assignment holds,
        // and the `all` mask cannot see two families swap places, so every
        // bit needs its own row.
        fixtures.extend(
            ArchivalFamily::ALL
                .iter()
                .map(|&family| (family.table(), FamilySet::of(&[family]))),
        );
        fixtures.extend([
            // Composition: two one-hots OR together, duplicates collapse.
            (
                "bond_and_slash_log",
                FamilySet::of(&[ArchivalFamily::Bond, ArchivalFamily::SlashLog]),
            ),
            // Pins the family COUNT too: adding a family widens this mask.
            ("all", FamilySet::ALL),
        ]);
        fixtures
    }
}

impl Fixtures for UndoLog {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Ordinals as literals: the snapshot pins the *row layout* (tag
        // bytes, u32 LE lengths, has_prior flag, the 32-byte post-image
        // digest on keyed entries), and must not move when a table is
        // appended to the catalogue. Every variant appears, with a
        // multi-byte key so the length prefix is visible in the hex.
        vec![
            ("empty", UndoLog::default()),
            (
                "inserted",
                UndoLog(vec![UndoEntry::Inserted {
                    table: TableOrdinal::from_index(0),
                    key: Box::new(1u64.to_le_bytes()),
                    post: post_image(&[0xb1, 0x0c]),
                }]),
            ),
            (
                "replaced_with_prior",
                UndoLog(vec![UndoEntry::Replaced {
                    table: TableOrdinal::from_index(19),
                    key: Box::from(*b"total_burned"),
                    prior: Some(Box::new(7u64.to_le_bytes())),
                    post: post_image(&9u64.to_le_bytes()),
                }]),
            ),
            (
                "replaced_absent",
                UndoLog(vec![UndoEntry::Replaced {
                    table: TableOrdinal::from_index(19),
                    key: Box::from(*b"k"),
                    prior: None,
                    post: post_image(&[1]),
                }]),
            ),
            (
                "three_in_write_order",
                UndoLog(vec![
                    UndoEntry::Inserted {
                        table: TableOrdinal::from_index(1),
                        key: Box::new([0x11; 32]),
                        post: post_image(&3u64.to_le_bytes()),
                    },
                    UndoEntry::Replaced {
                        table: TableOrdinal::from_index(18),
                        key: Box::new(2u64.to_le_bytes()),
                        prior: Some(Box::new([1])),
                        post: post_image(&[2]),
                    },
                    UndoEntry::Inserted {
                        table: TableOrdinal::from_index(12),
                        key: [5u64.to_le_bytes(), 0u64.to_le_bytes()]
                            .concat()
                            .into_boxed_slice(),
                        post: post_image(&[0x01; 9]),
                    },
                ]),
            ),
        ]
    }
}

impl Fixtures for SettlementEpochBlocks {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Literals: the snapshot pins the codec, not any consumer's schedule.
        let pin = |n| SettlementEpochBlocks::new(n).expect("non-zero fixture");
        vec![
            ("one", pin(1)),
            ("mainnet_shaped", pin(10_000)),
            ("byte_order", pin(0x0102_0304_0506_0708)),
        ]
    }
}

impl Fixtures for CoverageGaps {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Names, never indices: the bytes spell `CEN-…`. The first and last
        // census rows, so a row inserted anywhere between them does not
        // move this snapshot — which is the property the name encoding
        // buys and this fixture witnesses.
        let first = CenRow::ALL[0];
        let last = CenRow::ALL[CenRow::ALL.len() - 1];
        vec![
            ("none", CoverageGaps::NONE),
            ("first_row", CoverageGaps::of([first])),
            ("first_and_last", CoverageGaps::of([last, first])),
        ]
    }
}

impl Fixtures for PassedThroughFacts {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("none", PassedThroughFacts::NONE),
            ("burned", PassedThroughFacts::of_positions([3])),
            // Every field: the six-name spelling is the layout —
            // `cumulative_difficulty` left at SCHEMA_VERSION 7 (E6 slice 2).
            ("all", PassedThroughFacts::of_positions(0..6)),
        ]
    }
}

impl Fixtures for BlockHeight {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // The `u64` fixtures, named: the bytes are the scalar's, and the
        // snapshot is the witness that the newtype did not re-encode them.
        vec![
            ("zero", BlockHeight::ZERO),
            ("one", BlockHeight::from_raw(1)),
            ("byte_order", BlockHeight::from_raw(0x0102_0304_0506_0708)),
            ("max", BlockHeight::from_raw(u64::MAX)),
        ]
    }
}

impl Fixtures for RuleSetInForce {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Labels and values unchanged from when the codec was
        // `impl Canonical for RuleSetId`: the adapter moved the impl's
        // home, not its layout, so `rule_set_id.snap` must not move.
        vec![
            ("zero", RuleSetInForce(RuleSetId::from_raw(0))),
            ("genesis", RuleSetInForce(RuleSetId::GENESIS)),
            ("high_bit", RuleSetInForce(RuleSetId::from_raw(0x80))),
            ("max", RuleSetInForce(RuleSetId::from_raw(0xff))),
        ]
    }
}

impl Fixtures for PrunableHash {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", PrunableHash::from_bytes([0; 32])),
            (
                "ascending",
                PrunableHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
        ]
    }
}

impl Fixtures for PqcAuthHash {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", PqcAuthHash::from_bytes([0; 32])),
            (
                "ascending",
                PqcAuthHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
        ]
    }
}

impl Fixtures for AtomicUnits {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", AtomicUnits::ZERO),
            ("one", AtomicUnits::from_raw(1)),
            ("byte_order", AtomicUnits::from_raw(0x0102_0304_0506_0708)),
            ("max", AtomicUnits::from_raw(u64::MAX)),
        ]
    }
}

impl Fixtures for CurveTreeRoot {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", CurveTreeRoot::from_bytes([0; 32])),
            (
                "ascending",
                CurveTreeRoot::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
        ]
    }
}

impl Fixtures for BlockInfo {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "genesis_like",
                BlockInfo {
                    timestamp: Timestamp::from_raw(0),
                    coins_generated: AtomicUnits::from_raw(0),
                    weight: BlockWeight::from_raw(0),
                    cumulative_difficulty: CumulativeDifficulty::from_raw(1),
                    hash: BlockHash::NULL,
                    rct_outputs: 0,
                    long_term_weight: LongTermWeight::from_raw(0),
                    cumulative_tx_count: 0,
                    long_term_effective_median: LongTermWeight::from_raw(0),
                },
            ),
            // Every field distinct, difficulty straddling the lo/hi split so
            // the snapshot witnesses `bi_diff_lo` before `bi_diff_hi`.
            (
                "distinct_fields",
                BlockInfo {
                    timestamp: Timestamp::from_raw(0x0102_0304_0506_0708),
                    coins_generated: AtomicUnits::from_raw(2),
                    weight: BlockWeight::from_raw(3),
                    cumulative_difficulty: CumulativeDifficulty::from_raw((5u128 << 64) | 4),
                    hash: BlockHash::from_bytes([0xab; 32]),
                    rct_outputs: 6,
                    long_term_weight: LongTermWeight::from_raw(7),
                    cumulative_tx_count: 8,
                    long_term_effective_median: LongTermWeight::from_raw(9),
                },
            ),
        ]
    }
}

impl Fixtures for TxIndex {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "zero",
                TxIndex {
                    tx_id: TxStorageId::from_raw(0),
                    unlock_time: crate::codec::stored_timelock(0),
                    height: BlockHeight::from_raw(0),
                },
            ),
            (
                "distinct_fields",
                TxIndex {
                    tx_id: TxStorageId::from_raw(1),
                    unlock_time: crate::codec::stored_timelock(0x0102_0304_0506_0708),
                    height: BlockHeight::from_raw(3),
                },
            ),
        ]
    }
}

impl Fixtures for OutTx {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "zero",
                OutTx {
                    tx_hash: TxHash::from_bytes([0; 32]),
                    local_index: OutputIndexInTx::from_raw(0),
                },
            ),
            (
                "distinct_fields",
                OutTx {
                    tx_hash: TxHash::from_bytes([0x33; 32]),
                    local_index: OutputIndexInTx::from_raw(0x0102_0304_0506_0708),
                },
            ),
        ]
    }
}

impl Fixtures for OutKey {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "zero",
                OutKey {
                    output_id: OutputStorageId::from_raw(0),
                    pubkey: OneTimePubkey::from_bytes([0; 32]),
                    unlock_time: crate::codec::stored_timelock(0),
                    height: BlockHeight::from_raw(0),
                    commitment: CommitmentBytes::from_bytes([0; 32]),
                },
            ),
            // `output_id` in byte-order-witness form: a big-endian
            // regression reads `0102030405060708` at offset 0.
            (
                "distinct_fields",
                OutKey {
                    output_id: OutputStorageId::from_raw(0x0102_0304_0506_0708),
                    pubkey: OneTimePubkey::from_bytes([0x11; 32]),
                    unlock_time: crate::codec::stored_timelock(2),
                    height: BlockHeight::from_raw(3),
                    commitment: CommitmentBytes::from_bytes([0x22; 32]),
                },
            ),
        ]
    }
}

impl Fixtures for TxOutputIndices {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("empty", TxOutputIndices::default()),
            ("one", TxOutputIndices(vec![AmountIndex::from_raw(7)])),
            (
                "three",
                TxOutputIndices(vec![
                    AmountIndex::from_raw(0),
                    AmountIndex::from_raw(0x0102_0304_0506_0708),
                    AmountIndex::from_raw(u64::MAX),
                ]),
            ),
        ]
    }
}

/// The type name as written after `impl Canonical for`, for the source scan.
fn type_name<T>() -> &'static str {
    core::any::type_name::<T>()
        .rsplit("::")
        .next()
        .expect("type_name is non-empty")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render the snapshot text, having first held every fixture to the width
/// the codec declares. `fixed_width = n` in the header is a claim the
/// fixtures below it must witness: a codec declaring `Some(n)` while
/// emitting another length would otherwise round-trip, snapshot, and
/// still break the fixed-width storage contract (`DAEMON_REDB_STORE.md`
/// §11.1(b)). Checked in regeneration runs too — it is a property of the
/// codec, not of the committed text.
fn render<T: Fixtures>() -> String {
    let fixtures = T::fixtures();
    let mut labels = BTreeSet::new();
    for (label, value) in &fixtures {
        assert!(
            labels.insert(*label),
            "{}: duplicate fixture label `{label}`",
            T::NAME
        );
        let encoded = value.encode();
        if let Some(width) = T::FIXED_WIDTH {
            assert_eq!(
                encoded.len(),
                width,
                "{}: fixture `{label}` encodes to {} bytes but the codec declares \
                 FIXED_WIDTH = Some({width})",
                T::NAME,
                encoded.len(),
            );
        }
    }

    let mut out = String::from(SNAPSHOT_HEADER);
    out.push_str(&format!("codec = {}\n", T::NAME));
    match T::FIXED_WIDTH {
        Some(n) => out.push_str(&format!("fixed_width = {n}\n")),
        None => out.push_str("fixed_width = variable\n"),
    }
    out.push_str("[fixtures]\n");
    for (label, value) in &fixtures {
        out.push_str(&format!("{label} = {}\n", hex(&value.encode())));
    }
    out
}

/// Render the table catalogue: one row per definition, sorted by name
/// (redb addresses tables by name; declaration order is not layout), as
/// `name = shape<key, value>` in the `TypeName`s redb records on disk.
fn render_table_catalogue() -> String {
    let catalogue = schema::catalogue();
    assert!(!catalogue.is_empty(), "schema::catalogue() is empty");
    let mut rows = BTreeMap::new();
    for (ordinal, spec) in catalogue.iter().enumerate() {
        // The ordinal is part of the layout (schema module docs): the pop
        // journal names tables by it, so a reorder must move this snapshot
        // and take the version bump with it, even though the rows are
        // sorted by name for a stable diff. `map` is the catalogue's one
        // shape (rule 21); a second shape re-mints the word with its table.
        let row = format!("#{ordinal} map<{}, {}>", spec.key.name(), spec.value.name());
        assert!(
            rows.insert(spec.name.as_str(), row).is_none(),
            "duplicate table name `{}` in schema::catalogue()",
            spec.name
        );
    }
    let mut out = String::from(SNAPSHOT_HEADER);
    out.push_str(&format!("tables = {}\n[tables]\n", rows.len()));
    for (name, row) in rows {
        out.push_str(&format!("{name} = {row}\n"));
    }
    out
}

/// Render the property-cell catalogue: one row per cell, sorted by key
/// (`properties` orders by string comparison), as `key = scope<value>`.
fn render_property_catalogue() -> String {
    assert!(
        !PROPERTY_CELLS.is_empty(),
        "PROPERTY_CELLS is empty: the header cells must exist"
    );
    let mut rows = BTreeMap::new();
    for spec in PROPERTY_CELLS {
        let row = format!("{}<{}>", spec.scope.as_str(), spec.value);
        assert!(
            rows.insert(spec.key, row).is_none(),
            "duplicate properties key `{}` in PROPERTY_CELLS",
            spec.key
        );
    }
    let mut out = String::from(SNAPSHOT_HEADER);
    out.push_str(&format!("cells = {}\n[cells]\n", rows.len()));
    for (key, row) in rows {
        out.push_str(&format!("{key} = {row}\n"));
    }
    out
}

fn schemas_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

fn snapshot_path(stem: &str) -> PathBuf {
    schemas_dir().join(format!("{stem}.snap"))
}

/// What the driver did with a rendered snapshot.
enum Snapshot {
    /// `UPDATE_SNAPSHOTS` is set: the file was (re)written, nothing asserted.
    Written,
    /// The file exists and equals the rendering.
    Matched,
}

/// Assert-or-update driver, the same shape as the wallet's. `what` names
/// the subject in the failure text; `consequence` says what a mismatch
/// means for the store.
fn check_or_update(stem: &str, rendered: &str, what: &str, consequence: &str) -> Snapshot {
    let path = snapshot_path(stem);

    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(schemas_dir()).expect("create schemas dir");
        fs::write(&path, rendered)
            .unwrap_or_else(|e| panic!("cannot write snapshot {}: {e}", path.display()));
        eprintln!("UPDATE_SNAPSHOTS=1: wrote {}", path.display());
        return Snapshot::Written;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {}: {e}\n\
             hint: `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests` \
             to bootstrap, then bump SCHEMA_VERSION.",
            path.display()
        )
    });
    assert!(
        rendered == committed,
        "snapshot mismatch for {what}\n\
         --- committed ({}) vs. +++ current ---\n{}\n\
         {consequence} That is a layout change (DAEMON_REDB_STORE.md §11.1(b)) and\n\
         a rebuild for every existing store. If intentional:\n\
         \n\
           1. bump SCHEMA_VERSION in src/codec/schema_version.rs in the same commit;\n\
           2. regenerate: UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store codec::snapshot_tests\n\
           3. review the diff above.\n",
        path.display(),
        unified_diff(&committed, rendered),
    );
    Snapshot::Matched
}

fn check_or_update_snapshot<T: Fixtures>() {
    let rendered = render::<T>();
    if let Snapshot::Written = check_or_update(
        T::NAME,
        &rendered,
        &format!("codec `{}`", T::NAME),
        "The canonical encoding of a stored value has changed — digest-visible.",
    ) {
        return;
    }

    // The committed bytes decode back to the values that produced them.
    for (label, value) in T::fixtures() {
        let decoded = T::decode(&value.encode())
            .unwrap_or_else(|e| panic!("{}: fixture `{label}` does not decode: {e}", T::NAME));
        assert_eq!(decoded, value, "{}: fixture `{label}` round-trip", T::NAME);
    }
}

/// The table catalogue snapshot (`schemas/tables.snap`).
#[test]
fn table_catalogue_snapshot() {
    let rendered = render_table_catalogue();
    let _ = check_or_update(
        TABLE_CATALOGUE_SNAP,
        &rendered,
        "the table catalogue (schema.rs)",
        "A table was added, removed, renamed or re-typed.",
    );
}

/// The property-cell catalogue snapshot (`schemas/properties.snap`).
#[test]
fn property_catalogue_snapshot() {
    let rendered = render_property_catalogue();
    let _ = check_or_update(
        PROPERTY_CATALOGUE_SNAP,
        &rendered,
        "the property-cell catalogue (codec::property)",
        "A properties cell was added, removed, re-keyed, re-scoped or re-typed.",
    );
}

/// Source scan: every `TableDefinition::new(` / `MultimapTableDefinition::new(`
/// in `schema.rs` is in [`schema::catalogue`]. The `tables!` macro
/// catalogues everything declared through it; this catches a definition
/// declared beside it, which the snapshot above could not see.
///
/// Every constructor call is counted, and one whose name is not a string
/// literal on the same line fails the test rather than falling out of the
/// comparison: a definition this scan cannot read is one the two Python
/// schema gates cannot read either, so the literal spelling is the file's
/// grammar, not a preference.
#[test]
fn every_table_definition_is_catalogued() {
    const CONSTRUCTOR: &str = "TableDefinition::new(";
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/schema.rs"))
        .expect("read schema.rs");
    let mut declared = BTreeSet::new();
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") {
            continue;
        }
        for (at, _) in line.match_indices(CONSTRUCTOR) {
            let rest = &line[at + CONSTRUCTOR.len()..];
            let Some(name) = rest
                .strip_prefix('"')
                .and_then(|lit| lit.split_once('"'))
                .map(|(name, _)| name.to_owned())
            else {
                panic!(
                    "schema.rs: {line:?}: a table's name must be a string literal on the \
                     constructor's line; declare it inside `tables!` that way so the \
                     catalogue, this scan, and the Python schema gates all read it"
                );
            };
            assert!(
                declared.insert(name.clone()),
                "schema.rs: table {name:?} is declared twice"
            );
        }
    }
    assert!(
        !declared.is_empty(),
        "schema.rs: no table definitions parsed"
    );
    let catalogued: BTreeSet<String> = schema::catalogue().into_iter().map(|s| s.name).collect();
    assert_eq!(
        declared, catalogued,
        "every table definition in schema.rs must be declared inside `tables!` so it is catalogued"
    );
}

/// The string literal following `prefix` on `line`, if any.
fn quoted_after(line: &str, prefix: &str) -> Option<String> {
    let (_, rest) = line.split_once(prefix)?;
    rest.split_once('"').map(|(lit, _)| lit.to_owned())
}

/// Source scan of `property.rs` — the one module that can implement the
/// sealed [`PropertyCell`]. A cell written by hand beside the
/// `property_cells!` invocation compiles (same module as the seal) but
/// never reaches [`PROPERTY_CELLS`] or `properties.snap`, so the rule-42
/// gate would pass a layout change without its bump. Three things hold:
///
/// 1. the `impl PropertyCell for` sites are exactly the macro's template
///    and the test-only [`ProbeCell`] — spelling-independent, so a
///    hand-written cell is red however it writes its key;
/// 2. the only hand-spelled `const KEY` is the probe's;
/// 3. the macro's `key: "…"` rows are exactly [`PROPERTY_CELLS`].
///
/// Comment lines are skipped: the `compile_fail` doctest on the trait
/// declares an impostor on purpose.
#[test]
fn every_property_cell_is_catalogued() {
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/property.rs"))
            .expect("read property.rs");
    let mut impls = Vec::new();
    let mut macro_rows = BTreeSet::new();
    let mut hand_keys = BTreeSet::new();
    for line in text.lines().map(str::trim_start) {
        if line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("impl PropertyCell for ") {
            impls.push(rest.trim_end_matches('{').trim().to_owned());
        }
        if let Some(key) = quoted_after(line, "key: \"") {
            macro_rows.insert(key);
        }
        if let Some(key) = quoted_after(line, "const KEY: &'static str = \"") {
            hand_keys.insert(key);
        }
    }

    impls.sort();
    assert_eq!(
        impls,
        ["$name", "ProbeCell"],
        "property.rs: the `impl PropertyCell for` sites must be exactly the property_cells! \
         template and the test-only ProbeCell; declare a production cell through the macro so \
         PROPERTY_CELLS and properties.snap see it"
    );
    assert_eq!(
        hand_keys,
        BTreeSet::from([ProbeCell::KEY.to_owned()]),
        "property.rs: a hand-spelled `const KEY` other than the probe's is a cell outside the \
         catalogue"
    );

    let catalogued: BTreeSet<String> = PROPERTY_CELLS.iter().map(|c| c.key.to_owned()).collect();
    assert!(!catalogued.is_empty(), "PROPERTY_CELLS is empty");
    assert_eq!(
        macro_rows, catalogued,
        "the property_cells! rows in property.rs must be exactly PROPERTY_CELLS"
    );
    assert!(
        !catalogued.contains(ProbeCell::KEY),
        "the test-only probe must not be a catalogued cell"
    );
}

fn unified_diff(a: &str, b: &str) -> String {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    let mut out = String::new();
    for i in 0..a.len().max(b.len()) {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => out.push_str(&format!("  {x}\n")),
            (Some(x), Some(y)) => {
                out.push_str(&format!("- {x}\n"));
                out.push_str(&format!("+ {y}\n"));
            }
            (Some(x), None) => out.push_str(&format!("- {x}\n")),
            (None, Some(y)) => out.push_str(&format!("+ {y}\n")),
            (None, None) => unreachable!("i < max(len)"),
        }
    }
    out
}

/// Every codec with a snapshot, in one place. [`every_canonical_impl_has_a_snapshot`]
/// holds this list equal to the `impl Canonical for` set in the source tree.
macro_rules! snapshotted_codecs {
    ($($ty:ty => $test:ident),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                check_or_update_snapshot::<$ty>();
            }
        )*

        fn snapshotted() -> Vec<(&'static str, &'static str)> {
            vec![$((type_name::<$ty>(), <$ty as Canonical>::NAME)),*]
        }
    };
}

snapshotted_codecs! {
    u8 => codec_snapshot_u8,
    u64 => codec_snapshot_u64,
    Hash32 => codec_snapshot_hash32,
    SchemaVersion => codec_snapshot_schema_version,
    FamilySet => codec_snapshot_family_set,
    UndoLog => codec_snapshot_undo_log,
    SettlementEpochBlocks => codec_snapshot_settlement_epoch_blocks,
    CoverageGaps => codec_snapshot_rule_coverage_gaps,
    PassedThroughFacts => codec_snapshot_passed_through_facts,
    CurveTreeRoot => codec_snapshot_curve_root,
    BlockHeight => codec_snapshot_block_height,
    RuleSetInForce => codec_snapshot_rule_set_id,
    PrunableHash => codec_snapshot_prunable_hash,
    AtomicUnits => codec_snapshot_atomic_units,
    PqcAuthHash => codec_snapshot_pqc_auth_hash,
    BlockInfo => codec_snapshot_block_info,
    TxIndex => codec_snapshot_tx_index,
    OutTx => codec_snapshot_out_tx,
    OutKey => codec_snapshot_out_key,
    TxOutputIndices => codec_snapshot_tx_output_indices,
}

/// The gate asserts its own arming state (rule 47). `UPDATE_SNAPSHOTS`
/// disarms every comparison above into a write; a run with it set must
/// fail somewhere, or a regeneration run is indistinguishable from a
/// green one.
#[test]
fn codec_snapshot_assertions_are_armed() {
    assert!(
        env::var_os("UPDATE_SNAPSHOTS").is_none(),
        "UPDATE_SNAPSHOTS is set: every codec snapshot test in this module \
         OVERWROTE its `.snap` instead of comparing. Snapshots were regenerated; \
         re-run WITHOUT the variable to assert them."
    );
}

/// Source scan: every `impl Canonical for <T>` in **this crate's** `src/`
/// is registered in [`snapshotted_codecs!`], and the committed `.snap`
/// files are exactly the registered set's names plus the catalogue stems.
/// A codec cannot be added without a fixture, and a deleted codec cannot
/// leave an orphan snapshot behind.
///
/// # Why containment here and equality there
///
/// Since `Canonical` moved to `shekyl-store-codec`, some registered
/// codecs' impls are in that crate's tree — the scalars and the
/// vocabulary — and this scan cannot see them. That does **not** loosen
/// the other direction into something that cannot fail: a registry row
/// naming a codec that no longer exists is a **compile** error, because
/// [`snapshotted_codecs!`] expands each row to `<$ty as Canonical>::NAME`
/// and a `check_or_update_snapshot::<$ty>()` test. So "registered but not
/// implemented" is caught by the build, "implemented here but not
/// registered" is caught below, and the moved codecs' *bytes* are still
/// caught by their fixtures — which stay committed under this crate's
/// `schemas/` and still pair with [`SCHEMA_VERSION`], which is why
/// `.github/workflows/schema-snapshot.yml` triggers on the codec crate's
/// path too ([`workflow_gates_this_crate`]).
///
/// What is **not** asserted, named so it is not mistaken for covered: a
/// codec added to `shekyl-store-codec` for the *other* store and never
/// registered here. Its bytes are not this store's layout — and the moment
/// this store's layout names it, the table or property catalogue snapshot
/// moves (`tables.snap` carries `shekyl::Coded<{NAME}>`), which is the
/// same paired bump.
#[test]
fn every_canonical_impl_has_a_snapshot() {
    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        return;
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut impls = BTreeSet::new();
    scan_impls(&src, &mut impls);
    let registered: BTreeSet<&str> = snapshotted().into_iter().map(|(ty, _)| ty).collect();
    let local: BTreeSet<&str> = impls.iter().map(String::as_str).collect();
    // The scan's subject: a scan that found nothing would pass the
    // containment below for the wrong reason (rule 47).
    assert!(
        !local.is_empty(),
        "the `impl Canonical for T` scan of {} found nothing; the census is reading \
         the wrong tree",
        src.display()
    );
    let unregistered: Vec<&str> = local.difference(&registered).copied().collect();
    assert!(
        unregistered.is_empty(),
        "every `impl Canonical for T` under src/ must appear in `snapshotted_codecs!` \
         so it has a committed fixture snapshot; these do not: {unregistered:?}"
    );

    let mut names: BTreeSet<&str> = snapshotted().into_iter().map(|(_, name)| name).collect();
    assert_eq!(
        names.len(),
        registered.len(),
        "Canonical::NAME must be unique per codec"
    );
    for stem in CATALOGUE_SNAPS {
        assert!(
            names.insert(*stem),
            "a codec is NAMEd `{stem}`, which is a catalogue snapshot stem"
        );
    }
    let snaps: BTreeSet<String> = fs::read_dir(schemas_dir())
        .expect("read schemas dir")
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()? == "snap").then(|| path.file_stem()?.to_str().map(String::from))?
        })
        .collect();
    assert_eq!(
        snaps.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        names,
        "rust/shekyl-chain-store/schemas/*.snap must be exactly the registered codecs' NAMEs \
         plus the catalogue stems {CATALOGUE_SNAPS:?}"
    );
}

fn scan_impls(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan_impls(&path, out);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("impl") else {
                continue;
            };
            // Any `impl` of a trait *named* `Canonical` -- however the path
            // is spelled -- is a codec this census must pair with a
            // snapshot. Only the plain spelling is readable here, so every
            // other spelling (path-qualified, generic, trailing generics on
            // the type) is refused loudly instead of skipped: a codec the
            // scan cannot see is a codec Rule 42 cannot see.
            let Some((before, _)) = rest.split_once("Canonical for") else {
                continue;
            };
            if before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue; // some other trait whose name ends in `Canonical`
            }
            let ty = rest
                .strip_prefix(" Canonical for ")
                .and_then(|ty| ty.strip_suffix(" {"))
                .filter(|ty| !ty.is_empty() && ty.chars().all(|c| c.is_alphanumeric() || c == '_'))
                .unwrap_or_else(|| {
                    panic!(
                        "{}: {line:?}: spell codec impls exactly `impl Canonical for T {{` \
                         (no path prefix, no generics) so the snapshot census can read them",
                        path.display()
                    )
                })
                .to_owned();
            assert!(
                out.insert(ty.clone()),
                "duplicate `impl Canonical for {ty}`"
            );
        }
    }
}

/// Directories under `rust/` whose code sits on the path from a stored
/// value to its bytes: this crate and the closure of its **normal**
/// path dependencies, walked from the manifests — the same source cargo
/// resolves from — so a new edge is found without anyone listing it.
/// Dev- and build-dependencies are excluded: they cannot change a byte the
/// production binary writes. Members are directories relative to `rust/`,
/// not crate names, so the vendored `shekyl-oxide/crypto/*` crates the
/// closure reaches are held to the same coverage.
fn encoding_path_dirs() -> BTreeSet<String> {
    let rust = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("rust/ resolves");
    let mut seen = BTreeSet::new();
    let mut todo = vec![String::from("shekyl-chain-store")];
    while let Some(dir) = todo.pop() {
        if !seen.insert(dir.clone()) {
            continue;
        }
        let crate_dir = rust.join(&dir);
        let manifest = crate_dir.join("Cargo.toml");
        let text = fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
        for target in normal_path_dependencies(&text) {
            // A path dependency is relative to *its* manifest — a vendored
            // crate under shekyl-oxide/crypto/ names its siblings as `../x`
            // too — so resolve from there and re-express under rust/.
            let resolved = crate_dir.join(&target).canonicalize().unwrap_or_else(|e| {
                panic!("{}: path dependency {target:?}: {e}", manifest.display())
            });
            let under_rust = resolved.strip_prefix(&rust).unwrap_or_else(|_| {
                panic!(
                    "{}: path dependency {target:?} resolves outside rust/ ({}); the trigger \
                     pattern cannot cover it",
                    manifest.display(),
                    resolved.display()
                )
            });
            todo.push(under_rust.to_string_lossy().into_owned());
        }
    }
    // The walker's subject (rule 47): the three crates the move itself put
    // on this path must be found, or the walk read nothing and the coverage
    // assertion above would pass vacuously.
    for sentinel in ["shekyl-store-codec", "shekyl-types", "shekyl-units"] {
        assert!(
            seen.contains(sentinel),
            "encoding_path_dirs did not reach `{sentinel}`; the manifest walk is broken"
        );
    }
    seen
}

/// The `path = "…"` targets under a manifest's normal-dependency
/// sections (`[dependencies]` and `[target.*.dependencies]`; never dev or
/// build). House style writes each dependency inline on one line; any
/// other spelling of a path dependency is refused loudly rather than
/// skipped, because a dependency this walk cannot see is a crate the gate
/// cannot see.
fn normal_path_dependencies(manifest: &str) -> Vec<String> {
    let mut in_normal_deps = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(header) = trimmed.strip_prefix('[') {
            let header = header.trim_end_matches(']');
            assert!(
                !header.starts_with("dependencies."),
                "{trimmed}: spell path dependencies inline under [dependencies] so the \
                 encoding-path walk can read them"
            );
            in_normal_deps = header.ends_with("dependencies")
                && !header.contains("dev-dependencies")
                && !header.contains("build-dependencies");
            continue;
        }
        if !in_normal_deps || trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.split_once("path").map(|(_, r)| r) else {
            continue;
        };
        let Some(quoted) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let Some(after_quote) = quoted.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some((target, _)) = after_quote.split_once('"') else {
            continue;
        };
        out.push(target.to_owned());
    }
    out
}

/// Whether a `paths:` pattern of this workflow's trigger covers `rust/<dir>`.
/// Only the spellings the workflow uses are understood; any other `rust/`
/// pattern is refused rather than guessed at.
fn trigger_covers(pattern: &str, dir: &str) -> bool {
    match pattern.strip_prefix("rust/") {
        None => false,
        Some("**") => true,
        Some(rest) => {
            let prefix = rest.strip_suffix("/**").unwrap_or_else(|| {
                panic!("trigger pattern {pattern:?}: only `rust/**` and `rust/<dir>/**` are understood here")
            });
            dir == prefix || dir.starts_with(&format!("{prefix}/"))
        }
    }
}

/// The grammar the workflow parses `SCHEMA_VERSION` out of: the declaration
/// at column 0, the value a decimal literal inside `SchemaVersion::new(…)`.
/// The workflow's `sed` carries the same regex; both are pinned below.
const DECL_PREFIX: &str = "pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(";
const WORKFLOW_VERSION_REGEX: &str = r"SchemaVersion::new\(([0-9_]+)\)";

/// The workflow's job names, as `.github/workflows/schema-snapshot.yml`
/// spells them.
const ASSERT_JOB: &str = "assert-snapshots";
const BUMP_JOB: &str = "enforce-version-bump";
/// Region key for everything above `jobs:` — the trigger.
const TRIGGER: &str = "";

/// The workflow's **active** text, split by job: comment lines dropped,
/// then everything above `jobs:` under [`TRIGGER`] and each job's body
/// under its name. A needle found here is in YAML the runner executes; a
/// `cargo test` line commented out, or moved into a job that is not the
/// assert job, is not a gate (rule 47: read code, not prose).
fn active_yaml_by_job(yaml: &str) -> BTreeMap<String, String> {
    let mut regions: BTreeMap<String, String> = BTreeMap::new();
    let mut region = TRIGGER.to_owned();
    let mut in_jobs = false;
    for line in yaml.lines().map(str::trim_end) {
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        // A job heading: exactly two spaces, a name, a colon, nothing else.
        if in_jobs {
            if let Some(name) = line
                .strip_prefix("  ")
                .filter(|rest| !rest.starts_with(' '))
                .and_then(|rest| rest.strip_suffix(':'))
            {
                region = name.to_owned();
                continue;
            }
        }
        let text = regions.entry(region.clone()).or_default();
        text.push_str(line);
        text.push('\n');
    }
    regions
}

/// The workflow gates this crate: its trigger paths include the crate, its
/// assert job runs **this module** (the filter it uses selects
/// `module_path!()`, so the meta-tests run with the assertions), and its
/// paired-bump job names this crate's snapshot directory and version
/// constant and parses that constant in the grammar it is declared in.
/// Each needle is required in the **active** text of the **job that owns
/// it** ([`active_yaml_by_job`]). Without this, the gate could be silently
/// unwired — commented out, narrowed to the per-codec tests, or moved to a
/// job that does not run — by a workflow edit and every test here would
/// still pass.
#[test]
fn workflow_gates_this_crate() {
    let workflow =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/schema-snapshot.yml");
    let yaml = fs::read_to_string(&workflow)
        .unwrap_or_else(|e| panic!("read {}: {e}", workflow.display()));
    let run_line = format!("cargo test -p shekyl-chain-store {TEST_FILTER}");
    let needles = [
        (ASSERT_JOB, run_line.as_str()),
        (BUMP_JOB, "rust/shekyl-chain-store/schemas/"),
        (
            BUMP_JOB,
            "rust/shekyl-chain-store/src/codec/schema_version.rs",
        ),
        (BUMP_JOB, "SCHEMA_VERSION"),
        (BUMP_JOB, WORKFLOW_VERSION_REGEX),
    ];
    let regions = active_yaml_by_job(&yaml);
    // The trigger must cover every crate whose code can change a byte a
    // fixture pins — derived from the manifests, not listed here
    // ([`encoding_path_dirs`]): a list in this test would be the drift it
    // guards against.
    let trigger_patterns: Vec<&str> = regions
        .get(TRIGGER)
        .map(|text| {
            text.lines()
                .filter_map(|l| l.trim().strip_prefix("- \""))
                .filter_map(|l| l.strip_suffix('"'))
                .collect()
        })
        .unwrap_or_default();
    for dir in encoding_path_dirs() {
        assert!(
            trigger_patterns.iter().any(|p| trigger_covers(p, &dir)),
            "{}: the trigger {trigger_patterns:?} does not cover `rust/{dir}`, a crate on the \
             path from a stored value to its bytes; a change there must run this gate",
            workflow.display()
        );
    }
    for job in [ASSERT_JOB, BUMP_JOB] {
        assert!(
            regions.contains_key(job),
            "{}: no job `{job}` in the active YAML; the codec gate is not wired",
            workflow.display()
        );
    }
    for (job, needle) in needles {
        assert!(
            regions.get(job).is_some_and(|text| text.contains(needle)),
            "{}: the active text of {} does not contain {needle:?}; the codec gate is not wired",
            workflow.display(),
            if job == TRIGGER { "the trigger" } else { job }
        );
    }
    // The comment filter is load-bearing, not decoration: the same file
    // with the run line commented out must lose the needle.
    let disabled = yaml.replace(&run_line, &format!("# {run_line}"));
    assert_ne!(disabled, yaml, "the run line was not found to comment out");
    assert!(
        !active_yaml_by_job(&disabled)[ASSERT_JOB].contains(&run_line),
        "a commented-out `cargo test` line still reads as active"
    );
    // The filter the workflow runs is a substring of every test path in
    // this module and of nothing narrower: it selects the meta-tests too.
    assert!(
        module_path!().ends_with(TEST_FILTER),
        "TEST_FILTER {TEST_FILTER:?} does not select this module ({})",
        module_path!()
    );

    // The constant the workflow parses is declared in the grammar it parses:
    // the same extraction here yields the compiled value.
    let decl = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/schema_version.rs"),
    )
    .expect("read schema_version.rs");
    let declared: Vec<u64> = decl
        .lines()
        .filter_map(|l| l.strip_prefix(DECL_PREFIX))
        .map(|rest| {
            let digits: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            digits.parse().unwrap_or_else(|e| {
                panic!("SCHEMA_VERSION literal {digits:?} is not a decimal u64: {e}")
            })
        })
        .collect();
    assert_eq!(
        declared,
        vec![SCHEMA_VERSION.get()],
        "src/codec/schema_version.rs must declare SCHEMA_VERSION exactly once, at column 0, \
         as `{DECL_PREFIX}<decimal>);` — the workflow's paired-bump job parses the value \
         from that line at the PR's base and head and requires it to increase"
    );

    // A constant's doc is part of the edit (rule 91): the History list on
    // the declaration must name the current version.
    let entry = format!("/// - `{}` —", SCHEMA_VERSION.get());
    assert!(
        decl.contains(&entry),
        "src/codec/schema_version.rs: the History list has no entry {entry:?} for the \
         current SCHEMA_VERSION; record what changed when you bump"
    );
}
