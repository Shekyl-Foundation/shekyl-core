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
//! # One version per file, so each pairing is a glob
//!
//! The crate lays out two files ([`Layout`]), and each has one layout
//! version: the chain file's [`SCHEMA_VERSION`] (§11.1(a)), and the pool
//! file's own `POOL_SCHEMA_VERSION` (`DRS_E1_SPOOL.md` `SPL-Q8`: the pool
//! file is recreated at a mismatch, the chain file refused, so a pool-only
//! change must not cost a chain rebuild). `.github/workflows/schema-snapshot.yml`
//! therefore enforces *any change under `schemas/` ⟹ `SCHEMA_VERSION` has a
//! greater value in the same PR*, and the same of `pool_schemas/` and
//! `POOL_SCHEMA_VERSION`, with no per-codec registry to keep in sync. Each
//! row of [`snapshotted_codecs!`] names its layout. What this
//! module still has to guard is that each directory's snapshot **set** is
//! exactly its layout's registered codecs' names plus its catalogues, and that no codec
//! implemented here escapes registration
//! ([`every_canonical_impl_has_a_snapshot`] — read its *Why containment
//! here and equality there* for what the move did and did not cost), and
//! that the workflow is actually wired — runs this whole module,
//! and parses the declaration in the grammar it is written in
//! ([`workflow_gates_this_crate`]). A gate whose subject is absent is not a
//! gate (rule 47).
//!
//! # What this gate cannot see
//!
//! A gate written to prove coverage is itself a coverage claim, and it
//! inherits every hole in its own extractors. The ones that remain,
//! named so no reader mistakes them for covered:
//!
//! - **A crate removed from the workflow entirely.** The encoding-path
//!   walk seeds from the crates the workflow names in *both* its jobs and
//!   cross-checks the two; a crate deleted from both at once is invisible
//!   here. Each snapshot-owning crate's own test must assert its own
//!   presence (this one does through its needles; `shekyl-engine-state`'s
//!   through the `PAIRS` array).
//! - **Build scripts.** `build-dependencies` are excluded from the walk
//!   on the argument that they cannot change a byte the production
//!   binary writes; a `build.rs` that generated a layout would falsify
//!   that. None exists on this path today, and this test does not check.
//! - **Encoders outside the workspace.** A `redb` bump that re-rendered
//!   `TypeName` has no source file under `rust/` to match; it is reached
//!   only because `Cargo.lock` is under the trigger pattern.
//! - **Shared codecs this store's layout does not use.** A wallet-only
//!   codec in `shekyl-store-codec` has no daemon fixture by design; its
//!   bytes are the wallet store's to pin, and this gate says nothing
//!   about them until a daemon table or cell names the codec.
//! - **`Blob<K>` bytes.** A blob kind is not a codec: the bytes are the
//!   chain's own encoding, pinned by `shekyl-wire`'s KATs, not here.
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
    post_image, AltBlock, AltBlockFacts, AltBodies, BlockDraws, BlockInfo, BondRecord, Canonical,
    Coded, CompleteTreeSet, CoverageGaps, CurveTreeState, DrawableDigest, FirstPayingHeight,
    FollowingDegraded, HeldShard, Holdings, IssuedDigest, IssuedDraw, LayerHash, LeafCount, OutKey,
    OutTx, PoolRecord, ProbeCell, PropertyCell, QueuedBody, QueuedBundle, RMarket, RecordedPow,
    RuleSetInForce, SchemaVersion, SettlementEpochBlocks, SettlementRow, SigmaWorkMilli,
    SlashLogEntry, SlashedHolding, SupportCount, SupportIssued, TreeDepth, TxIndex,
    TxOutputIndices, UndoEntry, UndoLog, PROPERTY_CELLS, SCHEMA_VERSION,
};
use crate::ids::{AmountIndex, OutputStorageId, TxStorageId};
use crate::pool::PoolSchemaVersion;
use crate::schema::TableOrdinal;
use shekyl_chain_rules::{CenRow, RuleSetId};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    ArchivalLength, BadInterval, BlockHash, BlockHeight, BlockWeight, CommitmentBytes,
    CurveTreeRoot, GlobalOutputIndex, LongTermWeight, OneTimePubkey, OutputIndexInTx, PCanonicalId,
    PqcAuthHash, PrunableHash, SettlementEpoch, ShardId, Timestamp, TreeLeaf, TreePosition, TxHash,
};
use shekyl_units::AtomicUnits;

/// Catalogue snapshot stems. Not codec names;
/// [`every_canonical_impl_has_a_snapshot`] holds the two namespaces apart.
const TABLE_CATALOGUE_SNAP: &str = "tables";
const PROPERTY_CATALOGUE_SNAP: &str = "properties";
/// The pool file's table catalogue (`crate::pool::schema::catalogue`).
const POOL_CATALOGUE_SNAP: &str = "pool_tables";

/// The two files this crate lays out. Each has its own snapshot directory
/// and its own version constant, because they answer a layout mismatch
/// differently — the chain file refuses and is rebuilt from the block
/// corpus, the pool file is recreated (`DRS_E1_SPOOL.md` `SPL-Q8`) — so a
/// pool-only change must not demand a chain rebuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Layout {
    /// The consensus store file: `schemas/`, [`SCHEMA_VERSION`].
    Chain,
    /// The pool file: `pool_schemas/`,
    /// [`POOL_SCHEMA_VERSION`](crate::pool::POOL_SCHEMA_VERSION).
    Pool,
}

impl Layout {
    const ALL: [Self; 2] = [Self::Chain, Self::Pool];

    /// The snapshot directory, relative to the crate.
    const fn dir_name(self) -> &'static str {
        match self {
            Self::Chain => "schemas",
            Self::Pool => "pool_schemas",
        }
    }

    fn dir(self) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(self.dir_name())
    }

    /// The version constant the directory pairs with.
    const fn constant(self) -> &'static str {
        match self {
            Self::Chain => "SCHEMA_VERSION",
            Self::Pool => "POOL_SCHEMA_VERSION",
        }
    }

    /// The file that declares [`Self::constant`], relative to the crate.
    const fn source(self) -> &'static str {
        match self {
            Self::Chain => "src/codec/schema_version.rs",
            Self::Pool => "src/pool/schema_version.rs",
        }
    }

    /// The constant's value as compiled.
    fn version(self) -> u64 {
        match self {
            Self::Chain => SCHEMA_VERSION.get(),
            Self::Pool => crate::pool::POOL_SCHEMA_VERSION.get(),
        }
    }

    /// The declaration the workflow parses the value out of: at column 0,
    /// the value a decimal literal inside `<Type>::new(…)`.
    const fn decl_prefix(self) -> &'static str {
        match self {
            Self::Chain => "pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(",
            Self::Pool => {
                "pub const POOL_SCHEMA_VERSION: PoolSchemaVersion = PoolSchemaVersion::new("
            }
        }
    }

    /// The regex the workflow's `sed` carries for [`Self::decl_prefix`].
    const fn workflow_regex(self) -> &'static str {
        match self {
            Self::Chain => r"SchemaVersion = SchemaVersion::new\(([0-9_]+)\)",
            Self::Pool => r"PoolSchemaVersion = PoolSchemaVersion::new\(([0-9_]+)\)",
        }
    }

    /// The catalogue stems in this directory.
    const fn catalogues(self) -> &'static [&'static str] {
        match self {
            Self::Chain => &[TABLE_CATALOGUE_SNAP, PROPERTY_CATALOGUE_SNAP],
            Self::Pool => &[POOL_CATALOGUE_SNAP],
        }
    }

    /// What a mismatch costs an existing file.
    const fn consequence(self) -> &'static str {
        match self {
            Self::Chain => "a rebuild for every existing store",
            Self::Pool => "a recreate of every existing pool file",
        }
    }

    /// The header every snapshot in the directory starts with.
    fn header(self) -> String {
        format!(
            "# shekyl-chain-store canonical codec snapshot (rule 42). Do not edit by hand:\n\
             #   UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store {TEST_FILTER}\n\
             # and bump {} in {} in the same PR.\n",
            self.constant(),
            self.source()
        )
    }
}

/// The `cargo test` filter that selects exactly this module — what the
/// workflow's assert job runs. Pinned here so [`workflow_gates_this_crate`]
/// can hold the workflow to it and hold it to `module_path!()`.
const TEST_FILTER: &str = "codec::snapshot_tests";

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
                "removed",
                UndoLog(vec![UndoEntry::Removed {
                    table: TableOrdinal::from_index(36),
                    key: Box::new(3u64.to_le_bytes()),
                    prior: Box::new(500u64.to_le_bytes()),
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

// `PassedThroughFacts`' fixtures (`none`, `burned`, `all`) and its `.snap`
// left with the type at SCHEMA_VERSION 17 (E6 slice 7 wave B): the
// vocabulary had shrunk to one name at 16, and the last field became the
// verdict's.

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

impl Fixtures for TreePosition {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", TreePosition::from_raw(0)),
            ("byte_order", TreePosition::from_raw(0x0102_0304_0506_0708)),
            ("max", TreePosition::from_raw(u64::MAX)),
        ]
    }
}

impl Fixtures for GlobalOutputIndex {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", GlobalOutputIndex::from_raw(0)),
            (
                "byte_order",
                GlobalOutputIndex::from_raw(0x0102_0304_0506_0708),
            ),
            ("max", GlobalOutputIndex::from_raw(u64::MAX)),
        ]
    }
}

impl Fixtures for LeafCount {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", LeafCount::ZERO),
            ("byte_order", LeafCount::from_raw(0x0102_0304_0506_0708)),
            ("max", LeafCount::from_raw(u64::MAX)),
        ]
    }
}

impl Fixtures for TreeLeaf {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", TreeLeaf::from_bytes([0; TreeLeaf::LEN])),
            // Each scalar a distinct fill, so a scalar-order regression shows.
            (
                "four_scalars",
                TreeLeaf::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(0x10 * (i / 32 + 1) + i % 32).expect("fits a byte")
                })),
            ),
        ]
    }
}

impl Fixtures for FollowingDegraded {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "genesis_fork",
                FollowingDegraded {
                    fork_at: BlockHeight::ZERO,
                    tip: shekyl_types::BlockHash::from_bytes([0xd1; 32]),
                    work: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
                },
            ),
            (
                "byte_order",
                FollowingDegraded {
                    fork_at: BlockHeight::from_raw(0x0102_0304_0506_0708),
                    tip: shekyl_types::BlockHash::from_bytes([0xd2; 32]),
                    work: shekyl_difficulty::CumulativeDifficulty::from_raw(
                        0x1112_1314_1516_1718_191a_1b1c_1d1e_1f20,
                    ),
                },
            ),
        ]
    }
}

impl Fixtures for CurveTreeState {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("empty", CurveTreeState::EMPTY),
            (
                "grown",
                CurveTreeState {
                    root: CurveTreeRoot::from_bytes([0xc1; 32]),
                    depth: TreeDepth::from_raw(3),
                    leaf_count: LeafCount::from_raw(0x0102_0304_0506_0708),
                },
            ),
        ]
    }
}

impl Fixtures for LayerHash {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", LayerHash::from_bytes([0; 32])),
            (
                "ascending",
                LayerHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("32 indices fit a byte")
                })),
            ),
        ]
    }
}

impl Fixtures for BondRecord {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let base = BondRecord {
            hybrid_pubkey: vec![0x11; 4],
            bond_spend_pk: vec![0x22; 3],
            // 1,837 bytes of one fill: the field is fixed-width, so the
            // fixture pins where it sits and that no length precedes it.
            receipt_sign_pk: shekyl_types::archival::ReceiptSignPk::from_bytes(
                [0x44; shekyl_types::archival::RECEIPT_SIGN_PK_LEN],
            ),
            endpoint: [0x33; 32],
            join_settlement_epoch: SettlementEpoch::from_raw(3),
            bonded_total: AtomicUnits::from_raw(1_000_000),
            holdings: Holdings::CompleteTree,
            bad_intervals: vec![],
            claimed_settlement_epochs: vec![],
            first_paying_emission_height: None,
        };
        vec![
            // Every optional part absent: a complete tree, clean standing,
            // nothing claimed, never paid — the join-time record.
            ("complete_tree_at_join", base.clone()),
            // Every part present, each with a distinct value: two held
            // shards (insertion order kept, not sorted), an open bad interval
            // followed by a zero-length clean-close marker, two claimed
            // epochs strictly increasing, a first-paying height.
            (
                "compact_fully_populated",
                BondRecord {
                    holdings: Holdings::shard_set(vec![
                        HeldShard {
                            shard: ShardId::from_raw(42),
                            add_epoch: SettlementEpoch::from_raw(3),
                        },
                        HeldShard {
                            shard: ShardId::from_raw(7),
                            add_epoch: SettlementEpoch::from_raw(5),
                        },
                    ])
                    .expect("distinct, bounded"),
                    bad_intervals: vec![
                        BadInterval {
                            start_epoch: 4,
                            end_exclusive: BadInterval::OPEN_END,
                        },
                        BadInterval {
                            start_epoch: 9,
                            end_exclusive: 9,
                        },
                    ],
                    claimed_settlement_epochs: vec![
                        SettlementEpoch::from_raw(4),
                        SettlementEpoch::from_raw(6),
                    ],
                    first_paying_emission_height: FirstPayingHeight::new(BlockHeight::from_raw(
                        50_000,
                    )),
                    ..base
                },
            ),
        ]
    }
}
impl Fixtures for AltBodies {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // The alt block fixture's own coinbase, as a listed body: the codec
        // carries transactions as bytes it parses, and these are this
        // snapshot's literals (`test_block_bytes`).
        let block = crate::codec::BlockBody::parse(&super::alt::test_block_bytes(41))
            .expect("the fixture block parses");
        vec![
            ("none_listed", AltBodies::of(Vec::new())),
            (
                "one_listed",
                AltBodies::of(vec![block.miner_transaction.clone()]),
            ),
        ]
    }
}

impl Fixtures for AltBlock {
    fn fixtures() -> Vec<(&'static str, Self)> {
        use shekyl_types::BlockWeight;
        let facts = |weight: u64| AltBlockFacts {
            height: BlockHeight::from_raw(41),
            block_weight: BlockWeight::from_raw(weight),
            cumulative_difficulty: CumulativeDifficulty::from_raw((5u128 << 64) | 4), // lo = 4, hi = 5
            pow: crate::codec::RecordedPow {
                seed: shekyl_types::BlockHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("fits")
                })),
                pow: shekyl_types::PowHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(0x80 + i).expect("fits")
                })),
            },
        };
        let block = super::alt::test_block_bytes(41);
        vec![
            // Weight is mandatory. The two fixtures differ by the witness.
            (
                "weight_no_witness",
                AltBlock::checked(facts(2_048), &block, None).expect("fixture"),
            ),
            (
                "weight_and_witness",
                AltBlock::checked(facts(2_048), &block, Some(vec![0xA5; 40])).expect("fixture"),
            ),
        ]
    }
}

impl Fixtures for PoolRecord {
    fn fixtures() -> Vec<(&'static str, Self)> {
        use crate::codec::ReceivedHour;
        let stemmed = PoolRecord {
            received: ReceivedHour::from_raw(472_222),
            public: false,
        };
        vec![
            // Not yet public: the relay holds it in stem.
            ("unpublished", stemmed),
            // Fluffed, or carried by a block.
            (
                "public",
                PoolRecord {
                    public: true,
                    ..stemmed
                },
            ),
        ]
    }
}

impl Fixtures for PoolSchemaVersion {
    fn fixtures() -> Vec<(&'static str, Self)> {
        // Literals, not `POOL_SCHEMA_VERSION`, for the reason
        // `SchemaVersion`'s fixtures give.
        vec![
            ("zero", PoolSchemaVersion::new(0)),
            ("one", PoolSchemaVersion::new(1)),
            ("byte_order", PoolSchemaVersion::new(0x0102_0304_0506_0708)),
        ]
    }
}

impl Fixtures for SlashLogEntry {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let persona = PCanonicalId::from_bytes([0x5a; 32]);
        vec![
            (
                "compact_erase",
                SlashLogEntry {
                    persona,
                    shard: ShardId::from_raw(7),
                    epoch: SettlementEpoch::from_raw(0x0102_0304_0506_0708),
                    holding: SlashedHolding::Shard {
                        add_epoch: SettlementEpoch::from_raw(3),
                    },
                },
            ),
            (
                "complete_tree_demotion",
                SlashLogEntry {
                    persona,
                    shard: ShardId::from_raw(0),
                    epoch: SettlementEpoch::from_raw(1),
                    holding: SlashedHolding::CompleteTree,
                },
            ),
        ]
    }
}

impl Fixtures for RMarket {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero_coholders_written", RMarket::from_raw(0)),
            ("distinct", RMarket::from_raw(0x0102_0304_0506_0708)),
        ]
    }
}
impl Fixtures for SettlementRow {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let row = |passes, issued| SettlementRow::settle(passes, issued).expect("a row");
        vec![
            ("not_observed_one_issued", row(0, 1)),
            ("not_observed_two_issued", row(0, 2)),
            ("missed_no_pass", row(0, 3)),
            ("missed_one_pass", row(1, 3)),
            ("served_two_passes", row(2, 4)),
            ("served_three_passes", row(3, 9)),
            ("served_issued_saturated", row(2, 1000)),
        ]
    }
}
impl Fixtures for IssuedDraw {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "unpassed",
                IssuedDraw {
                    revealed_at: BlockHeight::from_raw(0x0102_0304_0506_0708),
                    passed: false,
                },
            ),
            (
                "passed",
                IssuedDraw {
                    revealed_at: BlockHeight::from_raw(0x0102_0304_0506_0708),
                    passed: true,
                },
            ),
        ]
    }
}
impl Fixtures for IssuedDigest {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("no_draws", IssuedDigest::ZERO),
            (
                "distinct",
                IssuedDigest::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i + 1).expect("fits")
                })),
            ),
        ]
    }
}
impl Fixtures for QueuedBundle {
    fn fixtures() -> Vec<(&'static str, Self)> {
        use shekyl_archival_retention::{BundleKept, BundleRef, PassBitmap};
        // Inline literals (rule 42): a kept part of nine economy draws with
        // two passes and two support draws with one, and a prunable hash
        // whose every byte is distinct.
        let kept = |count: u32, passes: &[u32], support: PassBitmap| BundleKept {
            h: BlockHeight::from_raw(0x0102_0304),
            seed: core::array::from_fn(|i| u8::try_from(0x40 + i).expect("fits")),
            passes: PassBitmap::from_passes(count, passes.iter().copied()).expect("in range"),
            support,
        };
        let prunable: [u8; 32] = core::array::from_fn(|i| u8::try_from(0x80 + i).expect("fits"));
        let at = |kept: BundleKept| QueuedBundle {
            reference: BundleRef::new(kept, prunable),
            tip_height: BlockHeight::from_raw(0x1112_1314),
            tip_hash: shekyl_types::BlockHash::from_bytes(core::array::from_fn(|i| {
                u8::try_from(0xC0 + i).expect("fits")
            })),
        };
        vec![
            (
                "economy_and_support",
                at(kept(
                    9,
                    &[0, 8],
                    PassBitmap::from_passes(2, [1]).expect("in range"),
                )),
            ),
            ("no_draws", at(kept(0, &[], PassBitmap::none()))),
        ]
    }
}

impl Fixtures for QueuedBody {
    fn fixtures() -> Vec<(&'static str, Self)> {
        use shekyl_archival_retention::{
            BundleBody, BundleRecord, BUNDLE_SIGNATURE_LEN, BUNDLE_WITNESS_KEY_LEN,
        };
        // Inline literals (rule 42): the codec carries the bytes and does
        // not parse the key or the signatures, so fills stand for them.
        let key = [0x5Au8; BUNDLE_WITNESS_KEY_LEN];
        let signature = [0xA5u8; BUNDLE_SIGNATURE_LEN];
        let record = BundleRecord {
            attempt: 2,
            anchor_height: BlockHeight::from_raw(0x2122_2324),
            delivery_digest: core::array::from_fn(|i| u8::try_from(i).expect("fits")),
            receipt: [0x3Cu8; BUNDLE_SIGNATURE_LEN],
        };
        vec![
            (
                "no_records",
                QueuedBody(BundleBody::new(&key, &signature, &[])),
            ),
            (
                "one_record",
                QueuedBody(BundleBody::new(&key, &signature, &[record])),
            ),
        ]
    }
}

impl Fixtures for RecordedPow {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![(
            "distinct",
            RecordedPow {
                seed: shekyl_types::BlockHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i).expect("fits")
                })),
                pow: shekyl_types::PowHash::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(0xA0 + i).expect("fits")
                })),
            },
        )]
    }
}
impl Fixtures for BlockDraws {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let row = |revealed| BlockDraws {
            count: 0x0102_0304,
            carry: 0x1112_1314,
            shortfall: 0x2122_2324_2526_2728,
            issued_short: 0x3132_3334,
            revealed,
        };
        vec![
            (
                "no_draws",
                BlockDraws {
                    count: 0,
                    carry: 0,
                    shortfall: 0,
                    issued_short: 0,
                    revealed: false,
                },
            ),
            ("in_flight", row(false)),
            ("revealed", row(true)),
        ]
    }
}
impl Fixtures for SupportIssued {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            (
                "unpassed",
                SupportIssued {
                    shard: ShardId::from_raw(7),
                    passed: false,
                },
            ),
            (
                "passed",
                SupportIssued {
                    shard: ShardId::from_raw(64),
                    passed: true,
                },
            ),
        ]
    }
}

impl Fixtures for SupportCount {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("none", SupportCount::new(0)),
            ("capped", SupportCount::new(10)),
            ("wide", SupportCount::new(0x0102_0304)),
        ]
    }
}
impl Fixtures for CompleteTreeSet {
    fn fixtures() -> Vec<(&'static str, Self)> {
        let id = |b: u8| PCanonicalId::from_bytes([b; 32]);
        vec![
            // The empty set is a written value, not an absent row.
            ("empty", CompleteTreeSet::default()),
            (
                "two",
                CompleteTreeSet::new(vec![id(0x11), id(0xa2)]).expect("ascending"),
            ),
        ]
    }
}
impl Fixtures for DrawableDigest {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            // Zero is a digest like any other, not an absent one.
            ("all_zero", DrawableDigest::from_bytes([0; 32])),
            (
                "distinct",
                DrawableDigest::from_bytes(core::array::from_fn(|i| {
                    u8::try_from(i + 1).expect("fits")
                })),
            ),
        ]
    }
}
impl Fixtures for SigmaWorkMilli {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", SigmaWorkMilli::from_raw(0)),
            ("distinct", SigmaWorkMilli::from_raw(0x0102_0304_0506_0708)),
        ]
    }
}
impl Fixtures for SettlementEpoch {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", SettlementEpoch::from_raw(0)),
            ("distinct", SettlementEpoch::from_raw(0x0102_0304_0506_0708)),
        ]
    }
}
impl Fixtures for ShardId {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", ShardId::from_raw(0)),
            ("distinct", ShardId::from_raw(0x0102_0304_0506_0708)),
        ]
    }
}
impl Fixtures for ArchivalLength {
    fn fixtures() -> Vec<(&'static str, Self)> {
        vec![
            ("zero", ArchivalLength::ZERO),
            ("distinct", ArchivalLength::from_raw(0x0102_0304_0506_0708)),
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
                    cumulative_archival_len: ArchivalLength::ZERO,
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
                    cumulative_archival_len: ArchivalLength::from_raw(10),
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
fn render<T: Fixtures>(layout: Layout) -> String {
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

    let mut out = layout.header();
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
    let mut out = Layout::Chain.header();
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
    let mut out = Layout::Chain.header();
    out.push_str(&format!("cells = {}\n[cells]\n", rows.len()));
    for (key, row) in rows {
        out.push_str(&format!("{key} = {row}\n"));
    }
    out
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
fn check_or_update(
    layout: Layout,
    stem: &str,
    rendered: &str,
    what: &str,
    consequence: &str,
) -> Snapshot {
    let path = layout.dir().join(format!("{stem}.snap"));

    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(layout.dir()).expect("create the snapshot dir");
        fs::write(&path, rendered)
            .unwrap_or_else(|e| panic!("cannot write snapshot {}: {e}", path.display()));
        eprintln!("UPDATE_SNAPSHOTS=1: wrote {}", path.display());
        return Snapshot::Written;
    }

    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {}: {e}\n\
             hint: `UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store {TEST_FILTER}` \
             to bootstrap, then bump {}.",
            path.display(),
            layout.constant()
        )
    });
    assert!(
        rendered == committed,
        "snapshot mismatch for {what}\n\
         --- committed ({}) vs. +++ current ---\n{}\n\
         {consequence} That is a layout change (DAEMON_REDB_STORE.md §11.1(b)) and\n\
         {}. If intentional:\n\
         \n\
           1. bump {} in {} in the same commit;\n\
           2. regenerate: UPDATE_SNAPSHOTS=1 cargo test -p shekyl-chain-store {TEST_FILTER}\n\
           3. review the diff above.\n",
        path.display(),
        unified_diff(&committed, rendered),
        layout.consequence(),
        layout.constant(),
        layout.source(),
    );
    Snapshot::Matched
}

fn check_or_update_snapshot<T: Fixtures>(layout: Layout) {
    let rendered = render::<T>(layout);
    let consequence = match layout {
        Layout::Chain => "The canonical encoding of a stored value has changed — digest-visible.",
        Layout::Pool => "The canonical encoding of a pool file value has changed.",
    };
    if let Snapshot::Written = check_or_update(
        layout,
        T::NAME,
        &rendered,
        &format!("codec `{}`", T::NAME),
        consequence,
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
        Layout::Chain,
        TABLE_CATALOGUE_SNAP,
        &rendered,
        "the table catalogue (schema.rs)",
        "A table was added, removed, renamed or re-typed.",
    );
}

/// The pool file's table catalogue snapshot (`pool_schemas/pool_tables.snap`).
/// The pool has no journal, so no ordinal is part of its layout; rows are
/// name-sorted with no `#n`.
#[test]
fn pool_catalogue_snapshot() {
    let catalogue = crate::pool::schema::catalogue();
    assert!(!catalogue.is_empty(), "pool::schema::catalogue() is empty");
    let mut rows = BTreeMap::new();
    for spec in &catalogue {
        let row = format!("map<{}, {}>", spec.key.name(), spec.value.name());
        assert!(
            rows.insert(spec.name.as_str(), row).is_none(),
            "duplicate table name `{}` in pool::schema::catalogue()",
            spec.name
        );
    }
    let mut out = Layout::Pool.header();
    out.push_str(&format!("tables = {}\n[tables]\n", rows.len()));
    for (name, row) in rows {
        out.push_str(&format!("{name} = {row}\n"));
    }
    let _ = check_or_update(
        Layout::Pool,
        POOL_CATALOGUE_SNAP,
        &out,
        "the pool file's table catalogue (pool/schema.rs)",
        "A pool table was added, removed, renamed or re-typed.",
    );
}

/// The property-cell catalogue snapshot (`schemas/properties.snap`).
#[test]
fn property_catalogue_snapshot() {
    let rendered = render_property_catalogue();
    let _ = check_or_update(
        Layout::Chain,
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
/// Each row names the [`Layout`] whose directory and version pin it.
macro_rules! snapshotted_codecs {
    ($($ty:ty => $test:ident in $layout:ident),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                check_or_update_snapshot::<$ty>(Layout::$layout);
            }
        )*

        fn snapshotted() -> Vec<(&'static str, &'static str, Layout)> {
            vec![$((type_name::<$ty>(), <$ty as Canonical>::NAME, Layout::$layout)),*]
        }
    };
}

snapshotted_codecs! {
    u8 => codec_snapshot_u8 in Chain,
    u64 => codec_snapshot_u64 in Chain,
    Hash32 => codec_snapshot_hash32 in Chain,
    SchemaVersion => codec_snapshot_schema_version in Chain,
    FamilySet => codec_snapshot_family_set in Chain,
    UndoLog => codec_snapshot_undo_log in Chain,
    SettlementEpochBlocks => codec_snapshot_settlement_epoch_blocks in Chain,
    CoverageGaps => codec_snapshot_rule_coverage_gaps in Chain,
    CurveTreeRoot => codec_snapshot_curve_root in Chain,
    BlockHeight => codec_snapshot_block_height in Chain,
    RuleSetInForce => codec_snapshot_rule_set_id in Chain,
    PrunableHash => codec_snapshot_prunable_hash in Chain,
    AtomicUnits => codec_snapshot_atomic_units in Chain,
    PqcAuthHash => codec_snapshot_pqc_auth_hash in Chain,
    BlockInfo => codec_snapshot_block_info in Chain,
    TxIndex => codec_snapshot_tx_index in Chain,
    OutTx => codec_snapshot_out_tx in Chain,
    OutKey => codec_snapshot_out_key in Chain,
    TxOutputIndices => codec_snapshot_tx_output_indices in Chain,
    TreePosition => codec_snapshot_tree_position in Chain,
    GlobalOutputIndex => codec_snapshot_global_output_index in Chain,
    LeafCount => codec_snapshot_leaf_count in Chain,
    TreeLeaf => codec_snapshot_tree_leaf in Chain,
    CurveTreeState => codec_snapshot_curve_tree_state in Chain,
    FollowingDegraded => codec_snapshot_following_degraded in Chain,
    LayerHash => codec_snapshot_layer_hash in Chain,
    BondRecord => codec_snapshot_bond_record in Chain,
    RMarket => codec_snapshot_r_market in Chain,
    SigmaWorkMilli => codec_snapshot_sigma_work_milli in Chain,
    SlashLogEntry => codec_snapshot_slash_log_entry in Chain,
    SettlementRow => codec_snapshot_settlement_row in Chain,
    IssuedDraw => codec_snapshot_issued_draw in Chain,
    IssuedDigest => codec_snapshot_issued_digest in Chain,
    BlockDraws => codec_snapshot_block_draws in Chain,
    SupportCount => codec_snapshot_support_count in Chain,
    SupportIssued => codec_snapshot_support_issued in Chain,
    DrawableDigest => codec_snapshot_drawable_digest in Chain,
    CompleteTreeSet => codec_snapshot_complete_tree_set in Chain,
    SettlementEpoch => codec_snapshot_settlement_epoch in Chain,
    ShardId => codec_snapshot_shard_id in Chain,
    ArchivalLength => codec_snapshot_archival_length in Chain,
    AltBlock => codec_snapshot_alt_block in Chain,
    AltBodies => codec_snapshot_alt_bodies in Chain,
    RecordedPow => codec_snapshot_recorded_pow in Chain,
    QueuedBundle => codec_snapshot_queued_bundle in Chain,
    QueuedBody => codec_snapshot_queued_body in Chain,
    PoolRecord => codec_snapshot_pool_record in Pool,
    PoolSchemaVersion => codec_snapshot_pool_schema_version in Pool,
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
/// # Three directions, because two were not enough
///
/// Since `Canonical` moved to `shekyl-store-codec`, some registered
/// codecs' impls are in that crate's tree — the scalars and the
/// vocabulary — and this scan cannot see them, so the scan is containment
/// (every impl *here* is registered), not equality. Two more checks close
/// what containment alone leaves open:
///
/// - **A registered codec that vanished** is a compile error:
///   [`snapshotted_codecs!`] expands each row to `<$ty as Canonical>::NAME`.
/// - **A used codec that was un-registered** is what neither of the above
///   sees, and it was the real hole: remove `BlockHeight` from the registry
///   and delete `block_height.snap`, and the scan, the build and the
///   snap-set equality all stay green while `tables.snap` still carries
///   `shekyl::Coded<block_height>` with no fixture pinning its bytes. So
///   the last assertion checks **need against supply**: every codec this
///   store's layout *uses* — a `Coded<{NAME}>` table value in
///   [`schema::catalogue`], a property cell's value codec in
///   [`PROPERTY_CELLS`] — must be a registered codec. The layout is the
///   demand, the registry is the supply; a coverage gate compares the two,
///   not the supply with itself.
///
/// A shared codec this store's layout does not use (a wallet-only codec in
/// `shekyl-store-codec`) is demanded by nothing here and stays
/// unregistered — by design, not by omission (module docs, *What this gate
/// cannot see*).
#[test]
fn every_canonical_impl_has_a_snapshot() {
    if env::var_os("UPDATE_SNAPSHOTS").is_some() {
        return;
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut impls = BTreeSet::new();
    scan_impls(&src, &mut impls);
    let registered: BTreeSet<&str> = snapshotted().into_iter().map(|(ty, ..)| ty).collect();
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
    let all_names: BTreeSet<&str> = snapshotted().into_iter().map(|(_, name, _)| name).collect();
    assert_eq!(
        all_names.len(),
        registered.len(),
        "Canonical::NAME must be unique per codec"
    );

    // Each directory holds exactly its layout's codecs and catalogues: a
    // snapshot filed under the other file's number would be versioned by
    // the wrong constant.
    for layout in Layout::ALL {
        let mut names: BTreeSet<&str> = snapshotted()
            .into_iter()
            .filter(|(.., l)| *l == layout)
            .map(|(_, name, _)| name)
            .collect();
        for stem in layout.catalogues() {
            assert!(
                names.insert(*stem),
                "a codec is NAMEd `{stem}`, which is a catalogue snapshot stem"
            );
        }
        let snaps: BTreeSet<String> = fs::read_dir(layout.dir())
            .unwrap_or_else(|e| panic!("read {}: {e}", layout.dir().display()))
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                (path.extension()? == "snap")
                    .then(|| path.file_stem()?.to_str().map(String::from))?
            })
            .collect();
        assert_eq!(
            snaps.iter().map(String::as_str).collect::<BTreeSet<_>>(),
            names,
            "rust/shekyl-chain-store/{}/*.snap must be exactly the {layout:?} layout's \
             registered codecs' NAMEs plus its catalogue stems {:?}",
            layout.dir_name(),
            layout.catalogues()
        );
    }

    // Need against supply (doc comment above), per file: every codec a
    // file's layout uses is registered under that file's layout. The
    // `Coded<V>` TypeName's prefix is derived from a real one rather than
    // spelled here, so this reads the same string `shape` writes.
    let probe = <Coded<BlockHeight> as redb::Value>::type_name();
    let coded_prefix = probe
        .name()
        .strip_suffix(&format!("{}>", BlockHeight::NAME))
        .expect("a Coded<V> TypeName ends in `{V::NAME}>`")
        .to_owned();
    let coded = |specs: Vec<schema::TableSpec>| -> BTreeSet<String> {
        let mut used = BTreeSet::new();
        for spec in specs {
            let value = spec.value.name();
            if let Some(rest) = value.strip_prefix(coded_prefix.as_str()) {
                let name = rest.strip_suffix('>').unwrap_or_else(|| {
                    panic!(
                        "table `{}`: value TypeName {value:?} is not `{coded_prefix}{{NAME}}>`",
                        spec.name
                    )
                });
                used.insert(name.to_owned());
            }
        }
        used
    };
    let mut chain_used = coded(schema::catalogue());
    for cell in PROPERTY_CELLS {
        chain_used.insert(cell.value.to_owned());
    }
    let pool_used = coded(crate::pool::schema::catalogue());
    for (layout, used) in [(Layout::Chain, chain_used), (Layout::Pool, pool_used)] {
        assert!(
            !used.is_empty(),
            "no {layout:?} table or property cell names a codec; the demand side read nothing"
        );
        let supply: BTreeSet<&str> = snapshotted()
            .into_iter()
            .filter(|(.., l)| *l == layout)
            .map(|(_, name, _)| name)
            .collect();
        let unpinned: Vec<&String> = used
            .iter()
            .filter(|n| !supply.contains(n.as_str()))
            .collect();
        assert!(
            unpinned.is_empty(),
            "the {layout:?} layout uses codecs with no fixture registered under it: \
             {unpinned:?} — register each in `snapshotted_codecs!` with `in {layout:?}` so \
             its bytes are pinned under {}",
            layout.constant()
        );
    }
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

/// The crates whose snapshot suites this workflow runs and versions — its
/// subject, read from the workflow itself so the seed set is not a list
/// here that the workflow could outgrow. Two instruments over one field:
/// the assert job's `cargo test -p <crate>` lines and the bump job's
/// `rust/<crate>/schemas/` mentions must name the same crates, or a suite
/// runs that is never versioned (or the reverse), which is a wiring defect
/// this test names rather than absorbs. This crate must be among them
/// (rule 47: the reader read *something*, and it read the right file).
///
/// What this cannot see: a crate removed from **both** jobs at once
/// (module docs, *What this gate cannot see*).
fn snapshot_owning_crates(regions: &BTreeMap<String, String>) -> BTreeSet<String> {
    let assert_text = regions
        .get(ASSERT_JOB)
        .map(String::as_str)
        .unwrap_or_default();
    let mut tested = BTreeSet::new();
    let mut words = assert_text.split_whitespace();
    while let Some(word) = words.next() {
        if word == "-p" {
            tested.insert(words.next().expect("`-p` names a crate").to_owned());
        }
    }
    let bump_text = regions
        .get(BUMP_JOB)
        .map(String::as_str)
        .unwrap_or_default();
    let mut versioned = BTreeSet::new();
    for (idx, _) in bump_text.match_indices("rust/") {
        let rest = &bump_text[idx + "rust/".len()..];
        let mut segments = rest.split('/');
        if let (Some(krate), Some("schemas")) = (segments.next(), segments.next()) {
            versioned.insert(krate.to_owned());
        }
    }
    assert_eq!(
        tested, versioned,
        "the assert job tests {tested:?} but the bump job versions {versioned:?}; every \
         snapshot-owning crate must appear in both"
    );
    assert!(
        tested.contains(env!("CARGO_PKG_NAME")),
        "the workflow's subject {tested:?} does not include this crate"
    );
    tested
}

/// Directories under `rust/` whose code sits on the path from a stored
/// value to its bytes: every snapshot-owning crate and the closure of its
/// **normal** path dependencies, walked from the manifests — the same
/// source cargo resolves from — so a new edge is found without anyone
/// listing it. Dev- and build-dependencies are excluded: they cannot change
/// a byte the production binary writes. Members are directories relative to
/// `rust/`, not crate names, so the vendored `shekyl-oxide/crypto/*` crates
/// the closure reaches are held to the same coverage.
fn encoding_path_dirs(seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let rust = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("rust/ resolves");
    let mut seen = BTreeSet::new();
    let mut todo: Vec<String> = seeds.iter().cloned().collect();
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

/// The `path = "…"` targets under a manifest's normal-dependency sections
/// (`[dependencies]` and `[target.<cfg>.dependencies]`; never dev or
/// build), read with a TOML parser rather than by line: a reader that
/// skipped a spelling it did not know — single quotes, a
/// `[dependencies.x]` table — would report a clean subset, and the
/// extractor is the gate. A `path` that is not a string is refused, not
/// skipped.
fn normal_path_dependencies(manifest: &str) -> Vec<String> {
    let table: toml::Table = manifest
        .parse()
        .unwrap_or_else(|e| panic!("manifest is not valid TOML: {e}"));
    let deps_of = |value: &toml::Value, section: &str| -> Vec<(String, toml::Value)> {
        let table = value
            .as_table()
            .unwrap_or_else(|| panic!("`{section}` is not a table"));
        table.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };
    let mut entries = Vec::new();
    if let Some(deps) = table.get("dependencies") {
        entries.extend(deps_of(deps, "dependencies"));
    }
    if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
        for (cfg, body) in targets {
            if let Some(deps) = body.get("dependencies") {
                entries.extend(deps_of(deps, &format!("target.{cfg}.dependencies")));
            }
        }
    }
    let mut out = Vec::new();
    for (name, spec) in entries {
        // `x = "1.0"` is a registry dependency: no path, nothing under rust/.
        let Some(spec) = spec.as_table() else {
            continue;
        };
        match spec.get("path") {
            None => {}
            Some(toml::Value::String(path)) => out.push(path.clone()),
            Some(other) => panic!("dependency `{name}`: `path` is {other:?}, not a string"),
        }
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
    // Each file's directory, declaring source, constant and the grammar the
    // workflow parses it in (the grammar this test holds the declaration
    // to, below).
    let paired: Vec<(Layout, String, String)> = Layout::ALL
        .into_iter()
        .map(|layout| {
            (
                layout,
                format!("rust/shekyl-chain-store/{}/", layout.dir_name()),
                format!("rust/shekyl-chain-store/{}", layout.source()),
            )
        })
        .collect();
    let mut needles: Vec<(&str, &str)> = vec![(ASSERT_JOB, run_line.as_str())];
    for (layout, dir, src) in &paired {
        needles.push((BUMP_JOB, dir.as_str()));
        needles.push((BUMP_JOB, src.as_str()));
        needles.push((BUMP_JOB, layout.constant()));
        needles.push((BUMP_JOB, layout.workflow_regex()));
    }
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
    let seeds = snapshot_owning_crates(&regions);
    for dir in encoding_path_dirs(&seeds) {
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

    // Each constant the workflow parses is declared in the grammar it
    // parses: the same extraction here yields the compiled value.
    for layout in Layout::ALL {
        let decl = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(layout.source()))
            .unwrap_or_else(|e| panic!("read {}: {e}", layout.source()));
        let declared: Vec<u64> = decl
            .lines()
            .filter_map(|l| l.strip_prefix(layout.decl_prefix()))
            .map(|rest| {
                let digits: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '_')
                    .filter(|c| *c != '_')
                    .collect();
                digits.parse().unwrap_or_else(|e| {
                    panic!(
                        "{} literal {digits:?} is not a decimal u64: {e}",
                        layout.constant()
                    )
                })
            })
            .collect();
        assert_eq!(
            declared,
            vec![layout.version()],
            "{} must declare {} exactly once, at column 0, as `{}<decimal>);` — the \
             workflow's paired-bump job parses the value from that line at the PR's base and \
             head and requires it to increase",
            layout.source(),
            layout.constant(),
            layout.decl_prefix()
        );

        // A constant's doc is part of the edit (rule 91): the History list
        // on the declaration must name the current version.
        let entry = format!("/// - `{}` —", layout.version());
        assert!(
            decl.contains(&entry),
            "{}: the History list has no entry {entry:?} for the current {}; record what \
             changed when you bump",
            layout.source(),
            layout.constant()
        );
    }
}
